#! /bin/bash

###  参数定义
# 应用名称
APP_NAME=CertViewer
This_Path=$(cd $(dirname $0);pwd)
# 编译后服务包目录
App_Path=$This_Path/$APP_NAME/app
# 打包后,安装包目录
Target_Path=$This_Path/$APP_NAME//result
# 脚本目录
Scripts_Path=$This_Path/$APP_NAME//scripts
# 源代码目录
Code_Path=$This_Path/../../


echo 脚本当前目录:$This_Path
echo 打包后应用目录:$App_Path
echo 源代码所在目录:$Code_Path
echo 源代码打包后服务目录:$Target_Path
echo 应用安装前后执行的脚本目录:$Scripts_Path


echo ----------

echo 开始编译源代码

cd $Code_Path
go build -o $Source_Path/$APP_NAME

echo "完成代码编译"

mkdir -p $Target_Path $Scripts_Path
cd $Target_Path
rm -f *.pkg

echo remove $Target_Path/$APP_NAME.pkg

echo 开始构建应用
pkgbuild --root $App_Path --install-location /Applications/$APP_NAME/Contents/ --identifier com.github.wegoo.$APP_NAME --version 1.0 --scripts $Scripts_Path  $Target_Path/$APP_NAME.pkg


echo "完成 查看: " $App_Path/$APP_NAME.pkg
