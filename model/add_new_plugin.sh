#########################################################################################
# Author:      Juyin
# Date:        2017/4/21
# Description: 本脚本实现快速增加一个wireshark插件的模板
#			   This shell file devote to generate a wireshark plugin template quickly.
#########################################################################################
#!/bin/bash

#新插件名称
#New plugin name
NEW_PLUGIN=model
NEW_PLUGIN_UPPER=`echo $NEW_PLUGIN|awk '{print toupper($0)}'`
WIRESHARK_PLUGIN_BASE=.
WIRESHARK_BASE=${WIRESHARK_PLUGIN_BASE}/../..
#cd /mnt/hgfs/Desktop/test3/plugins/amin
next='\n'


#检查是否已经添加过该插件
#Check the plugin whether is exist
cat ${WIRESHARK_BASE}/Makefile.am|grep ${NEW_PLUGIN}.la
if [ "$?" == "0" ];then
	echo -e "\a This Plugin ${NEW_PLUGIN} exist"
	exit -1
fi


#sed -i "s/m2m.la.*$/m2m.la test.la \\\/"    ${WIRESHARK_BASE}/Makefile.am


#添加插件相关
##1.添加Makefile.am
##First,add Makefile.am
sed -i "s+m2m\/m2m.la.*$+m2m\/m2m.la \\\\\n\\t-dlopen plugins\/${NEW_PLUGIN}\/${NEW_PLUGIN}.la \\\+"    ${WIRESHARK_BASE}/Makefile.am

##2.添加CMakeList.txt 
##Secend,add CMakeList.txt 
sed -i "s+plugins\/m2m+plugins\/m2m \\n\\t\\tplugins\/${NEW_PLUGIN} +"    ${WIRESHARK_BASE}/CMakeLists.txt

##3.configure
sed -i "s+plugins\/m2m\/Makefile +plugins\/m2m\/Makefile plugins\/${NEW_PLUGIN}\/Makefile +"    ${WIRESHARK_BASE}/configure
sed -i "/\"plugins\/m2m\/Makefile.*$/a\\  \\  \"plugins\/${NEW_PLUGIN}\/Makefile\") CONFIG_FILES=\"\$CONFIG_FILES plugins\/${NEW_PLUGIN}\/Makefile\" ;;"   ${WIRESHARK_BASE}/configure

##4.configure.ac
sed -i "/plugins\/m2m\/Makefile.*$/a\\ \\ plugins\/${NEW_PLUGIN}\/Makefile"   ${WIRESHARK_BASE}/configure.ac

##5.Makefile.in
sed -i "/irda.la plugins\/m2m\/m2m.la/a@HAVE_PLUGINS_TRUE@\tplugins\/${NEW_PLUGIN}\/${NEW_PLUGIN}.la \\\\"   ${WIRESHARK_BASE}/Makefile.in
sed -i "/-dlopen plugins\/m2m\/m2m.la/a@HAVE_PLUGINS_TRUE@\t-dlopen plugins\/${NEW_PLUGIN}\/${NEW_PLUGIN}.la \\\\"   ${WIRESHARK_BASE}/Makefile.in

##6.Makefile.nmake
sed -i "/plugins\\\m2m\\\/a \\\tplugins\\\\${NEW_PLUGIN}\\\\\\*\\.sbr\\t\\t\\\\"   ${WIRESHARK_BASE}/Makefile.nmake

##7.epan/Makefile.am
sed -i "/plugins\/m2m\/packet-m2m.c/a\\\t..\/plugins\/${NEW_PLUGIN}\/packet-${NEW_PLUGIN}.c \\\\"   ${WIRESHARK_BASE}/epan/Makefile.am

##8.epan/Makefile.in
sed -i "/plugins\/m2m\/packet-m2m.c/a@ENABLE_STATIC_TRUE@@HAVE_PLUGINS_TRUE@ ..\/plugins\/${NEW_PLUGIN}\/packet-${NEW_PLUGIN}.c \\\\"   ${WIRESHARK_BASE}/epan/Makefile.in

##9.plugins/Makefile.am
sed -i "/m2m/a\\\t${NEW_PLUGIN} \\\\"   ${WIRESHARK_BASE}/plugins/Makefile.am

##10.plugins/Makefile.in
sed -i "/m2m/a\\\t${NEW_PLUGIN} \\\\"   ${WIRESHARK_BASE}/plugins/Makefile.in

##11.plugins/Makefile.nmake
sed -i "/m2m/a\\\t${NEW_PLUGIN}     \\t\\\\"   ${WIRESHARK_BASE}/plugins/Makefile.nmake


#修改模板/Modify template
##1.检查是否在新插件目录下
new_base=`echo ${PWD}`
new_folder=${new_base##*/}
#echo $new_folder

if [ "$new_folder" != "${NEW_PLUGIN}" ];then
	echo "Please modify plugin name"
	echo "folder:$new_folder"
	echo "plugin:$NEW_PLUGIN"
	exit -1
fi

##2.得到模板中的插件名称
OLD_PLUGIN=`cat moduleinfo.h|grep '#define PACKAGE'|head -n 1|cut -d "\"" -f 2`
OLD_PLUGIN_UPPER=`echo $OLD_PLUGIN|awk '{print toupper($0)}'`
#echo ${OLD_PLUGIN}
#echo ${OLD_PLUGIN_UPPER}

FILES='*.c *.h AUTH* Cha* CM* CO* Makefile* module* packet* plugin*'

##3.修改大写的插件名称
sed -i "s/${OLD_PLUGIN_UPPER}/${NEW_PLUGIN_UPPER}/g"    ${FILES}

##4.修改小写的插件名称
sed -i "s/${OLD_PLUGIN}/${NEW_PLUGIN}/g"   ${FILES}

##5.修改packet文件
mv  packet-${OLD_PLUGIN}.c  packet-${NEW_PLUGIN}.c






