#! /bin/bash

APP_NAME=CertViewer

Source_Path=/Users/$USER/$APP_NAME/app
Target_Path=/Users/$USER/$APP_NAME/result
Scripts_Path=/Users/$USER/$APP_NAME/scripts
echo 

mkdir -p $Target_Path
cd $Target_Path
rm -f *.pkg

echo remove  $Target_Path/$APP_NAME.pkg

pkgbuild --root $Source_Path --install-location /Applications/$APP_NAME/Contents/ --identifier com.github.wegoo.$APP_NAME --version 1.0 --scripts $Scripts_Path  $Target_Path/$APP_NAME.pkg


echo "打包完成 查看: " $Source_Path/$APP_NAME.pkg
