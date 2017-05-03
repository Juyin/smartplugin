/* packet-model.c
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "config.h"
#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>

#include <string.h>

/* Wireshark ID of the MODEL protocol */
static int proto_model = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t data_handle = NULL;//子域句柄
static dissector_handle_t model_handle;

static int global_model_port = 999;//端口号

#define MODEL_MSG_TYPE_TEXT 0
#define MODEL_MSG_TYPE_FILE 1
static const value_string packettypenames[] =
{
    { MODEL_MSG_TYPE_TEXT, "TEXT" },
    { MODEL_MSG_TYPE_FILE, "FILE" },
    { 0, NULL }
};

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_model()
*/
/** attempt at defining the protocol */
static gint hf_model = -1;
static gint hf_model_header = -1;
static gint hf_model_length = -1;
static gint hf_model_type = -1;
static gint hf_model_text = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_model = -1;
static gint ett_model_header = -1;
static gint ett_model_length = -1;
static gint ett_model_type = -1;
static gint ett_model_text = -1;

#define PROTO_TAG_MODEL  "MODEL"

#define PACKET_LENGTH_LENGTH    4
#define PACKET_TYPE_LENGTH  1

static void dissect_model(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*****************************************************************************
** Function     : proto_reg_handoff_model
** Description  : 协议句柄注册
** Input        : void: 
** Output       : None
** Return Value : None
*****************************************************************************/
void proto_reg_handoff_model(void)
{
    static gboolean initialized = FALSE;

    if (!initialized)
    {
        data_handle = find_dissector("data");
        //生成解析程序句柄
        //create_dissector_handle的函数原型为：dissector_handle_t create_dissector_handle(dissector_t dissector, int proto) ;
        model_handle = create_dissector_handle(dissect_model, proto_model);
        //dissector_add("tcp.port", global_model_port, model_handle);
        //挂载解析函数句柄,void dissector_add(const char *name, guint32 pattern, dissector_handle_t handle);
        //该函数添加dissector_handle_t对象到系统的dissector table中，其中name为对应协议的名称或者过滤器名称，pattern为协议ID。
        dissector_add_uint("tcp.port", global_model_port, model_handle);
    }
}

/*****************************************************************************
** Function     : proto_register_model
** Description  : 协议解析器函数注册
** Input        : void: 
** Output       : None
** Return Value : SUCCESS/FAILURE
*****************************************************************************/
void proto_register_model(void)
{
    /* A header field is something you can search/filter on.
    *
    * We create a structure to register our fields. It consists of an
    * array of hf_register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */
    //此结构是一个用于代表协议中用于解析各个字段信息的结构。
    //使用的时候，通常使用数组方式来代表协议中的诸多字段
    static hf_register_info hf[] =
    {
        {
            &hf_model,//协议字段地址
            {
                "Data", //协议字段名称信息
                "model.data1",//过滤字符串
                FT_NONE, //字段类型
                BASE_NONE,//数字显示方式
                NULL, //此协议字段值显示的内容
                0x0,// 部分代表的含义为字段敏感掩码，类型为整数，通常写成十六进制，如0x80、0x0f00 等。如：我们需要处理的字段为一个字节的高四位，但是前面第四部分索要处理的部分写的是一个字节，此处我们就可以填入0xf0，来去掉低四位对相关计算的影响。
                "MODEL PDU", //字段详细描述
                HFILL  //常用结构填充宏
            }
        },
        {
            &hf_model_header,
            {
                "Header", "model.header", FT_NONE, BASE_NONE, NULL, 0x0,
                "MODEL Header", HFILL
            }
        },
        {
            &hf_model_length,
            {
                "Package Length", "model.len", FT_UINT32, BASE_DEC, NULL, 0x0,
                "Package Length", HFILL
            }
        },
        {
            &hf_model_type,
            {
                "Type", "model.type", FT_UINT8, BASE_DEC, VALS(packettypenames), 0x0,
                "Package Type", HFILL
            }
        },
        {
            &hf_model_text,
            {
                "Text", "model.text", FT_STRING, BASE_NONE, NULL, 0x0,
                "Text", HFILL
            }
        }
    };
    
    static gint *ett[] =
    {
        &ett_model,
        &ett_model_header,
        &ett_model_length,
        &ett_model_type,
        &ett_model_text
    };

    //注册协议名称等
	/**
    proto_register_protocol的原型为：
	int proto_register_protocol(const char *name, const char *short_name, const char *filter_name)
		函数参数为三个字符串：
		name为协议全名（用于详细信息部分显示);
		short_name为协议简称（用于相关界面上的简单表示与描述）
		filter_name为协议过滤字符串（用于在过滤器处输入过滤规则时的匹配字符串），过滤字符串必须小写。
		函数返回值是协议ID，后续注册相关的函数都会用到它。
	*/    
    proto_model = proto_register_protocol("MODEL Protocol", "MODEL", "model");

    //协议各字段注册
    proto_register_field_array(proto_model, hf, array_length(hf));

    //子树字段注册
    proto_register_subtree_array(ett, array_length(ett));
    
    //挂载
    register_dissector("model", dissect_model, proto_model);
}

/*****************************************************************************
** Function     : dissect_model
** Description  : 
** Input        : tvb: 为传给解析器函数的有关数据包内容的指针
**                pinfo: 当前数据包在wireshark 或tshark 界面上数据包列表中信息
**                tree: 数据包详细信息中的树形结构
** Output       : None
** Return Value : 
*****************************************************************************/
static void dissect_model(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *model_item = NULL;
    proto_item *model_sub_item = NULL;
    proto_tree *model_tree = NULL;
    proto_tree *model_header_tree = NULL;
    guint32 offset = 0;
    guint32 length = 0;
    gint8 type = -1;
    tvbuff_t *data_tvb = NULL;

    //设置col显示
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MODEL);
    col_clear(pinfo->cinfo, COL_INFO);
    

    if (tree)   /* we are being asked for details */
    {
     /*
        proto_item *proto_tree_add_item(proto_tree *tree,const int hfindex,tvbuf_t *tvb,const gint start,gint length,const guint encoding);
        此函数会在参数tree 中添加一个结点。
        hfindex 指明和此结点关联的协议字段，
        tvb 为维护数据包内容的指针，
        start 为选中协议字段后，原始数据包中高亮部分，相对起始数据包的偏移
        Length 为需要高亮的字节数，为-1 表示一直到数据包结束，即高亮剩余全部。
        Encoding用以表示数据包中的内容在协议字段中处理的时候，是否需要字节序的转换。返回值为添加的结点。
     */        
        model_item = proto_tree_add_item(tree, proto_model, tvb, 0, -1, FALSE);

        /*函数会为结点参数pi 添加一个子树，并与idx 关联，idx 会保存树形结点的状态*/
        model_tree = proto_item_add_subtree(model_item, ett_model);

        model_sub_item = proto_tree_add_item(model_tree, hf_model_header, tvb, offset, 5, FALSE);
        model_header_tree = proto_item_add_subtree(model_sub_item, ett_model);

        /** Length */
        length = tvb_get_letohl(tvb, offset);
        proto_tree_add_uint(model_header_tree, hf_model_length, tvb, offset, PACKET_LENGTH_LENGTH, length);
        offset += PACKET_LENGTH_LENGTH;

        /** Type */
        type = tvb_get_guint8(tvb, offset);   // Get the type byte
        proto_tree_add_item(model_header_tree, hf_model_type, tvb, offset, PACKET_TYPE_LENGTH, FALSE);
        offset += PACKET_TYPE_LENGTH;

        /** Show the type in pinfo */
		/*            
		col_set_str(column_info cinfo,const gint el,const gchar *str);
		此函数可以设置el 的值对应的列的值为字符串str，
		cinfo 估计为数据包所在行。与此类似的函数还有col_clear，col_append_str，check_col 等。代码示例见后面的图。
		*/
		col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d Info Type:[%s]",
					 pinfo->srcport, pinfo->destport,
					 val_to_str(type, packettypenames, "Unknown Type:0x%02x"));

		col_append_str(pinfo->cinfo, COL_INFO, ", test");
        

        if (type == MODEL_MSG_TYPE_TEXT)
        {
            proto_tree_add_item(model_tree, hf_model_text, tvb, offset, length - PACKET_TYPE_LENGTH, FALSE);
        }
        else
        {
            //得到剩下的数据
            data_tvb = tvb_new_subset_remaining(tvb, offset);
            /* No sub-dissection occured, treat it as raw data */
            call_dissector(data_handle, data_tvb, pinfo, tree);
        }

    }
}

