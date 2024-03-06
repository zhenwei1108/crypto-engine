package main

import (
	"crypto-engine/src/x509"
	"encoding/asn1"
	"encoding/base64"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()

	// 创建一个窗口对象
	myWindow := myApp.NewWindow("cert reader")

	// 创建一个标签组件
	helloLabel := widget.NewLabel("Welcome !")

	input := widget.NewEntry()
	input.Wrapping = fyne.TextWrapBreak
	input.SetPlaceHolder("please input certificate text, use base64")

	out := widget.NewEntry()

	parseButton := widget.NewButton("parse", func() {
		certBytes, _ := base64.StdEncoding.DecodeString(input.Text)
		var certificates x509.Certificate
		_, err := asn1.Unmarshal(certBytes, &certificates)
		if err != nil {
			out.SetPlaceHolder(err.Error())
		}
		out.SetPlaceHolder(certificates.SignatureAlgorithm.Algorithm.String())

	})

	// 创建一个按钮组件
	closeButton := widget.NewButton("close", func() {
		myApp.Quit()
	})
	myWindow.Resize(fyne.NewSize(600, 600))
	// 创建一个容器并添加组件
	content := container.NewVBox(
		helloLabel,
		input,
		out,
		parseButton,
		closeButton,
	)

	// 将容器添加到窗口
	myWindow.SetContent(content)

	// 显示窗口
	myWindow.ShowAndRun()
}
