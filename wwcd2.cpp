#include "wwcd.h"

vector<string> split(const char *str, char c = ' ')
{
	vector<string> result;

	do
	{
		const char *begin = str;

		while (*str != c && *str)
			str++;

		result.push_back(string(begin, str));
	} while (0 != *str++);

	return result;
}


int is_supported_arch()
{
	/*if (ph.id == PLFM_ARM)
		return 1;*/

	if (ph.id == PLFM_386)
		return 1;

	return 0;
}

inline bool is_thumb_ea(ea_t ea)
{
	/*  if ( !has_arm() )
		return true;*/
	sel_t t = get_segreg(ea, 21 /*T*/);
	return t != BADSEL && t != 0;
}

csh get_capstone_handle_for_ea(ea_t ea)
{
	segment_t *seg = getseg(ea);
	int bitness = seg->bitness;
	cs_arch arch = CS_ARCH_ARM;
	cs_mode mode = CS_MODE_LITTLE_ENDIAN;
	csh handle;

	switch (ph.id) {
	case PLFM_ARM:
		mode = CS_MODE_ARM;
		if (bitness == 2) {
			arch = CS_ARCH_ARM64;
		}
		else {
			arch = CS_ARCH_ARM;
			if (is_thumb_ea(ea)) {
				mode = CS_MODE_THUMB;
			}
		}
		break;
	case PLFM_386:
		arch = CS_ARCH_X86;
		switch (bitness) {
		case 0:
			mode = CS_MODE_16;
			break;
		case 1:
			mode = CS_MODE_32;
			break;
		case 2:
			mode = CS_MODE_64;
			break;
		}
		break;
	case PLFM_PPC:
		arch = CS_ARCH_PPC;
		break;
	default:
		/* hmm this should not happen */
		msg("error: cannot configure capstone because unsupported CPU\n");
		return 0;
	}

	if (inf.mf) {
		mode = (cs_mode)(mode | CS_MODE_BIG_ENDIAN);
	}

	if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
		msg("error: failed to initialize capstone\n");
		return 0;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	return handle;
}

// processor callback

static int idaapi processor_extension_callback(void * /*user_data*/, int event_id, va_list va)
{
	qnotused(va);
	ea_t ea;
	switch (event_id)
	{
	case processor_t::custom_out:
		char code[32];
		int size = cmd.size;
		ea = cmd.ea;

		csh handle = get_capstone_handle_for_ea(ea);

		if (handle == 0) {
			return 0;
		}

		if (size > 32) {
			return 0;
		}

		if (get_many_bytes(ea, &code, size) == 0) {
			return 0;
		}

		char buf[MAXSTR];
		init_output_buffer(buf, sizeof(buf));
		cs_insn *insn;
		char temp[32] = "";
		std::string result;
		size_t count = cs_disasm(handle, (uint8_t *)&code, size, ea, 1, &insn);

		if (count > 0)
		{
			int align = strlen(insn[0].mnemonic) % ALIGN_SPACE;

			if (align == 0)
				align = 1;
			else
				align = ALIGN_SPACE - align;

			if (cs_insn_group(handle, insn, CS_GRP_JUMP) || cs_insn_group(handle, insn, CS_GRP_CALL))
				out_line(insn[0].mnemonic, COLOR_SEGNAME);
			else
				out_line(insn[0].mnemonic, COLOR_INSN);

			for (int i = 0; i < align; i++)
			OutChar(' ');

			int op_count = insn->detail->x86.op_count;
			for (int i = 0; i < op_count; i++)
			{
				const auto & op = insn->detail->x86.operands[i];
				switch (op.type)
				{
				case X86_OP_REG:
				{
					result = cs_reg_name(handle, x86_reg(op.reg));
				}
				out_line(result.c_str(), COLOR_REG);
				break;

				case X86_OP_IMM:
				{
					if (cs_insn_group(handle, insn, CS_GRP_JUMP) || cs_insn_group(handle, insn, CS_GRP_CALL)) {
						qstring *c = new qstring("");
						get_ea_name(c, op.imm);
						if (c->length() > 0) {
							sprintf_s(temp, c->c_str());
						}
						out_line(temp, COLOR_DEMNAME);
					}
					else {
						sprintf_s(temp, "0x%02Xh", op.imm);
						out_line(temp, COLOR_NUMBER);
					}
					result = temp;
				}
				/*out_line(result.c_str(), COLOR_NUMBER);*/
				
				break;

				case X86_OP_MEM:
				{
					
					const auto & mem = op.mem;
					int op_size = (op.size > 0 && op.size <= 64) ? op.size : 0;

					sprintf_s(temp, "%s ptr ", mem_size[op_size].c_str());
					
					out_line(temp, COLOR_KEYWORD);
					
					const char* segment_text = cs_reg_name(handle, x86_reg(mem.segment));
					
					if (mem.segment == X86_REG_INVALID) //segment not set
					{
						switch (x86_reg(mem.base))
						{
						case X86_REG_ESP:
						case X86_REG_RSP:
						case X86_REG_EBP:
						case X86_REG_RBP:
							segment_text = "ss";
							break;
						default:
							segment_text = "ds";
							break;
						}
					}
					out_line(segment_text, COLOR_SEGNAME);
					out_line(":", COLOR_DEFAULT);

					out_line("[", COLOR_DEFAULT);
					//result += "[";
					if (op.mem.base == X86_REG_RIP)  //rip-relative (#replacement)
					{
						sprintf_s(temp, "0x%02X", size_t(insn->address) + op.mem.disp + insn->size);
						//result += temp;
						out_line(temp, COLOR_ADDR);
					}
					else //#base + #index * #scale + #displacement
					{
						bool prepend_plus = false;
						
						if (mem.base)
						{
							//result += cs_reg_name(handle, x86_reg(mem.base));
							out_line(cs_reg_name(handle, x86_reg(mem.base)), COLOR_REG);
							prepend_plus = true;
						}

						if (mem.index)
						{
							if (prepend_plus) {
								//result += " + ";
								out_line(" + ", COLOR_DEFAULT);
							}
								

							//result += cs_reg_name(handle, x86_reg(mem.index));
							out_line(cs_reg_name(handle, x86_reg(mem.index)), COLOR_REG);

							if (mem.scale > 1) // index * scale
							{
								out_line("*", COLOR_DEFAULT);
								//result += "*";
								sprintf_s(temp, "0x%02X", mem.scale);
								//result += temp;
								out_line(temp, COLOR_NUMBER);
							}
							
							prepend_plus = true;
						}

						if (mem.disp)
						{
							string operatorText = " + ";
							if (mem.disp < 0)
							{
								operatorText = " - ";
								sprintf_s(temp, "0x%02X", mem.disp * -1);
							}
							else
								sprintf_s(temp, "0x%02X", mem.disp);
							
							if (prepend_plus) {
								//result += operatorText;
								out_line(operatorText.c_str(), COLOR_DEFAULT);
							}
							out_line(temp, COLOR_NUMBER);
							//result += temp;
						}
						else if (!prepend_plus)
						{
							//result += "0";
							out_line("0", COLOR_NUMBER);
						}
							
					}
				}
				out_line("]", COLOR_DEFAULT);
				//result += "]";
				//out_line(result.c_str(), COLOR_DATA);
				break;

				case X86_OP_FP:
				{
					sprintf_s(temp, "%f", op.fp);
					out_line(temp, COLOR_UNKNOWN);
				}
				case X86_OP_INVALID:
				{
					out_line("???", COLOR_UNKNOWN);
				}
				break;
				}
				
				result = "";
				if (i < op_count - 1)
					out_line(", ", COLOR_DEFAULT);
			}
			
			/*int align = strlen(insn[0].mnemonic) % 16;
			
			if (align == 0) 
				align = 1; 
			else 
				align = 16 - align;

			out_line(insn[0].mnemonic, COLOR_INSN);
			for (int i = 0; i < align; i++) 
				OutChar(' ');
		
			vector<string> ops = split(insn[0].op_str);
			for (int i = 0; i < ops.size(); i++)
			{
				out_line(ops[i].c_str(), COLOR_REG);
				out_line(" ", COLOR_DEFAULT);
			}*/
		}
		else {
			OutBadInstruction();
		}
		cs_free(insn, count);
		cs_close(&handle);

		term_output_buffer();
		gl_comm = 1;
		MakeLine(buf);
		return 2;


	}
	return 0;											// event is not processed
}

//--------------------------------------------------------------------------
// Action for popup menu entry
//--------------------------------------------------------------------------

struct wwcd_ah_t : public action_handler_t
{
	virtual int idaapi activate(action_activation_ctx_t *ctx)
	{

		csh handle;
		cs_insn *insn;
		char buffer[32];
		int len;

		handle = get_capstone_handle_for_ea(ctx->cur_ea);

		if (handle == 0) {
			msg("error: initializing capstone\n");
			return 1;
		}

		/* we assume that an instruction is not longer than 32 bytes */
		len = 32;
		if (get_many_bytes(ctx->cur_ea, &buffer, len) == 0) {
			return 0;
		}

		size_t count = cs_disasm(handle, (uint8_t *)&buffer, len, ctx->cur_ea, 1, &insn);
		if (count > 0) {
			size_t j;
			for (j = 0; j < count; j++) {
				msg("0x");
				if (sizeof(ea_t) == 8) {
					msg("%016llx", (uint64_t)insn[j].address);
				}
				else {
					msg("%08x", (uint32_t)insn[j].address);
				}
				msg(":");
				if (true) {
					int s;
					msg("\t");
					for (s = 0; s < insn[j].size; s++) {
						msg("%02x ", insn[j].bytes[s]);
					}
					for (; s < 4; s++) msg("	 ");
				}
				msg("\t%s\t\t%s\n", insn[j].mnemonic,
					insn[j].op_str);
			}
			cs_free(insn, count);
		}
		else {
			msg("error: capstone failed to disassemble this opcode.\n");
		}

		cs_close(&handle);

		return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t *ctx)
	{
		bool ok = ctx->form_type == BWN_DISASM;
		return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
	}
};

struct wwcdcv_ah_t : public action_handler_t
{
	virtual int idaapi activate(action_activation_ctx_t *ctx)
	{
		qnotused(ctx);
		use_capstone_view = !use_capstone_view;
		update_action_checked("WWCDCV", use_capstone_view);

		if (use_capstone_view)
		{
			hook_to_notification_point(HT_IDP, processor_extension_callback, NULL);
		}
		else {
			unhook_from_notification_point(HT_IDP, processor_extension_callback);
		}

		request_refresh(IWID_DISASMS);

		return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t *ctx)
	{
		bool ok = ctx->form_type == BWN_DISASM;
		return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
	}
};

static wwcd_ah_t wwcd_ah;
static wwcdcv_ah_t wwcdcv_ah;
static action_desc_t wwcd_action = ACTION_DESC_LITERAL("WWCD", "What Would Capstone Decode?", &wwcd_ah, "Ctrl+Alt+C", NULL, icon);
static action_desc_t wwcdcv_action = ACTION_DESC_LITERAL("WWCDCV", "Capstone View", &wwcdcv_ah, "Ctrl+Alt+Shift+C", NULL, icon);

static int idaapi ui_callback(void *, int code, va_list va)
{
	if (code == ui_finish_populating_tform_popup)
	{
		TForm *form = va_arg(va, TForm *);
		TPopupMenu *popup_handle = va_arg(va, TPopupMenu *);

		if (get_tform_type(form) == BWN_DISASM)
		{
			attach_action_to_popup(form, popup_handle, "");
			attach_action_to_popup(form, popup_handle, "WWCD");
			attach_action_to_popup(form, popup_handle, "WWCDCV", "Hide", SETMENU_APP);
		}
	}
	return 0;
}

int idaapi init(void)
{
	if (!is_supported_arch())
		return PLUGIN_SKIP;

	msg("----------------------------------------\n");
	msg("What Would Capstone Decode? v0.9.2\n(C) Copyright 2015-2016 SektionEins GmbH\n");
	msg("----------------------------------------\n");

	icon = load_custom_icon(capstone_icon, sizeof(capstone_icon), "png");
	wwcd_action.icon = icon;
	wwcdcv_action.icon = icon;

	register_action(wwcd_action);
	register_action(wwcdcv_action);
	update_action_checkable("WWCDCV", true);
	update_action_checked("WWCDCV", false);
	hook_to_notification_point(HT_UI, ui_callback, NULL);

	return PLUGIN_KEEP;
}

void idaapi term(void)
{
	if (use_capstone_view)
	{
		unhook_from_notification_point(HT_IDP, processor_extension_callback);
	}
	unhook_from_notification_point(HT_UI, ui_callback);
}


void idaapi run(int /*arg*/)
{
}

//--------------------------------------------------------------------------
static const char comment[] = "What Would Capstone Decode? helper plugin";
static const char help[] =
"A IDA module that shows you how the Capstone disassembly\n"
"library would disassemble the current opcode.\n"
"\n";

static const char wanted_name[] = "WWCD";

static const char wanted_hotkey[] = "";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC | PLUGIN_HIDE,
	init,
	term,
	run,
	comment,
	help,
	wanted_name,
	wanted_hotkey
};
