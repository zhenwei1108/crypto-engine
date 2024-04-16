#! /bin/bash

###  参数定义
# 应用名称
APP_NAME=CertViewer
# 编译后服务包目录
Source_Path=/Users/$USER/$APP_NAME/app
# 打包后,安装包目录
Target_Path=/Users/$USER/$APP_NAME/result
# 脚本目录
Scripts_Path=/Users/$USER/$APP_NAME/scripts
# 源代码目录
Code_Path=/Users/$USER/code-space/GolandProjects/learn/crypto-engine


cd $Code_Path
go build -o $Source_Path/$APP_NAME

echo "完成代码编译"

mkdir -p $Target_Path $Scripts_Path
cd $Target_Path
rm -f *.pkg

echo remove  $Target_Path/$APP_NAME.pkg

pkgbuild --root $Source_Path --install-location /Applications/$APP_NAME/Contents/ --identifier com.github.wegoo.$APP_NAME --version 1.0 --scripts $Scripts_Path  $Target_Path/$APP_NAME.pkg


echo "打包完成 查看: " $Source_Path/$APP_NAME.pkg
