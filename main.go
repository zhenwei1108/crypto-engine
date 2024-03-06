package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()

	// 创建一个窗口对象
	myWindow := myApp.NewWindow("crypto engine")

	// 创建一个标签组件
	helloLabel := widget.NewLabel("Welcome !")

	input := widget.NewEntry()
	input.Wrapping = fyne.TextWrapBreak
	input.SetPlaceHolder("输入证书Base64")
	//新标签
	label := widget.NewLabel("")
	input.OnSubmitted = func(data string) {
		label.SetText(data)
		//input.SetText(data)
	}

	// 创建一个按钮组件
	closeButton := widget.NewButton("close", func() {
		myApp.Quit()
	})
	myWindow.Resize(fyne.NewSize(600, 600))
	// 创建一个容器并添加组件
	content := container.NewVBox(
		helloLabel,
		input,
		closeButton,
	)

	// 将容器添加到窗口
	myWindow.SetContent(content)

	// 显示窗口
	myWindow.ShowAndRun()
}
