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
static dissector_handle_t data_handle = NULL;//������
static dissector_handle_t model_handle;

static int global_model_port = 999;//�˿ں�

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
** Description  : Э����ע��
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
        //���ɽ���������
        //create_dissector_handle�ĺ���ԭ��Ϊ��dissector_handle_t create_dissector_handle(dissector_t dissector, int proto) ;
        model_handle = create_dissector_handle(dissect_model, proto_model);
        //dissector_add("tcp.port", global_model_port, model_handle);
        //���ؽ����������,void dissector_add(const char *name, guint32 pattern, dissector_handle_t handle);
        //�ú������dissector_handle_t����ϵͳ��dissector table�У�����nameΪ��ӦЭ������ƻ��߹��������ƣ�patternΪЭ��ID��
        dissector_add_uint("tcp.port", global_model_port, model_handle);
    }
}

/*****************************************************************************
** Function     : proto_register_model
** Description  : Э�����������ע��
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
    //�˽ṹ��һ�����ڴ���Э�������ڽ��������ֶ���Ϣ�Ľṹ��
    //ʹ�õ�ʱ��ͨ��ʹ�����鷽ʽ������Э���е�����ֶ�
    static hf_register_info hf[] =
    {
        {
            &hf_model,//Э���ֶε�ַ
            {
                "Data", //Э���ֶ�������Ϣ
                "model.data1",//�����ַ���
                FT_NONE, //�ֶ�����
                BASE_NONE,//������ʾ��ʽ
                NULL, //��Э���ֶ�ֵ��ʾ������
                0x0,// ���ִ���ĺ���Ϊ�ֶ��������룬����Ϊ������ͨ��д��ʮ�����ƣ���0x80��0x0f00 �ȡ��磺������Ҫ������ֶ�Ϊһ���ֽڵĸ���λ������ǰ����Ĳ�����Ҫ����Ĳ���д����һ���ֽڣ��˴����ǾͿ�������0xf0����ȥ������λ����ؼ����Ӱ�졣
                "MODEL PDU", //�ֶ���ϸ����
                HFILL  //���ýṹ����
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

    //ע��Э�����Ƶ�
	/**
    proto_register_protocol��ԭ��Ϊ��
	int proto_register_protocol(const char *name, const char *short_name, const char *filter_name)
		��������Ϊ�����ַ�����
		nameΪЭ��ȫ����������ϸ��Ϣ������ʾ);
		short_nameΪЭ���ƣ�������ؽ����ϵļ򵥱�ʾ��������
		filter_nameΪЭ������ַ����������ڹ�������������˹���ʱ��ƥ���ַ������������ַ�������Сд��
		��������ֵ��Э��ID������ע����صĺ��������õ�����
	*/    
    proto_model = proto_register_protocol("MODEL Protocol", "MODEL", "model");

    //Э����ֶ�ע��
    proto_register_field_array(proto_model, hf, array_length(hf));

    //�����ֶ�ע��
    proto_register_subtree_array(ett, array_length(ett));
    
    //����
    register_dissector("model", dissect_model, proto_model);
}

/*****************************************************************************
** Function     : dissect_model
** Description  : 
** Input        : tvb: Ϊ�����������������й����ݰ����ݵ�ָ��
**                pinfo: ��ǰ���ݰ���wireshark ��tshark ���������ݰ��б�����Ϣ
**                tree: ���ݰ���ϸ��Ϣ�е����νṹ
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

    //����col��ʾ
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MODEL);
    col_clear(pinfo->cinfo, COL_INFO);
    

    if (tree)   /* we are being asked for details */
    {
     /*
        proto_item *proto_tree_add_item(proto_tree *tree,const int hfindex,tvbuf_t *tvb,const gint start,gint length,const guint encoding);
        �˺������ڲ���tree �����һ����㡣
        hfindex ָ���ʹ˽�������Э���ֶΣ�
        tvb Ϊά�����ݰ����ݵ�ָ�룬
        start Ϊѡ��Э���ֶκ�ԭʼ���ݰ��и������֣������ʼ���ݰ���ƫ��
        Length Ϊ��Ҫ�������ֽ�����Ϊ-1 ��ʾһֱ�����ݰ�������������ʣ��ȫ����
        Encoding���Ա�ʾ���ݰ��е�������Э���ֶ��д����ʱ���Ƿ���Ҫ�ֽ����ת��������ֵΪ��ӵĽ�㡣
     */        
        model_item = proto_tree_add_item(tree, proto_model, tvb, 0, -1, FALSE);

        /*������Ϊ������pi ���һ������������idx ������idx �ᱣ�����ν���״̬*/
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
		�˺�����������el ��ֵ��Ӧ���е�ֵΪ�ַ���str��
		cinfo ����Ϊ���ݰ������С�������Ƶĺ�������col_clear��col_append_str��check_col �ȡ�����ʾ���������ͼ��
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
            //�õ�ʣ�µ�����
            data_tvb = tvb_new_subset_remaining(tvb, offset);
            /* No sub-dissection occured, treat it as raw data */
            call_dissector(data_handle, data_tvb, pinfo, tree);
        }

    }
}

