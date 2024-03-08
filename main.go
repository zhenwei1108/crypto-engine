package main

import (
	"crypto-engine/src/x509"
	"encoding/asn1"
	"encoding/base64"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	_ "github.com/lengzhao/font/autoload" //这个可以让你识别中文
	"image/color"
	"strings"
	"time"
)

// go的发布时间，作为日期的格式
const DateTime = "2006-01-02 15:04:05"

func main() {
	myApp := app.New()
	// 创建一个窗口对象
	myWindow := myApp.NewWindow("Cert Reader")
	myWindow.Resize(fyne.NewSize(600, 600))
	//显示时间，每秒更新
	showTime := freshTimeSeconds()
	// 表头
	helloLabel := widget.NewLabel("欢迎访问全球最大的同性交友网站： https://github.com/zhenwei1108 ")

	//输入
	base64Input := widget.NewEntry()

	//input.Wrapping = fyne.text
	base64Input.SetPlaceHolder("输入Base64的X.509证书")

	hexInput := widget.NewEntry()
	hexInput.SetPlaceHolder("输入Base64的X.509证书")

	//定义一个切片，用于构造表格，key-value
	resultTable := []fyne.CanvasObject{}
	//签名算法标识符
	signAlgText := canvas.NewText("", color.Black)
	//颁发者
	issueText := canvas.NewText("", color.Black)
	//有效期
	validityText := canvas.NewText("", color.Black)

	serNoText := canvas.NewText("", color.Black)

	resultTable = append(resultTable, signAlgText, issueText, serNoText, validityText)
	parseButton := widget.NewButton("解析证书", func() {
		base64InputString := strings.ReplaceAll(base64Input.Text, " ", "")
		hexInputString := strings.ReplaceAll(hexInput.Text, " ", "")
		if StringIsEmpty(hexInputString) {
			//todo
		}
		certBytes, _ := base64.StdEncoding.DecodeString(base64InputString)

		var certificate x509.Certificate
		_, err := asn1.Unmarshal(certBytes, &certificate)
		if err != nil {
			signAlgText.Text = err.Error()
		}
		signAlgText.Text = "签名算法: " + matchSignAlgFromOid(certificate.SignatureAlgorithm.Algorithm.String()) //非必填项可以跳过
		issueText.Text = "颁发者: " + certificate.TbsCertificate.Issuer.String()
		validityText.Text = "有效期: " + certificate.TbsCertificate.Validity.NotAfter.String()
		serNoText.Text = "证书序列号: " + strings.ToUpper(certificate.TbsCertificate.SerialNumber.Text(16))
	})
	// 创建一个按钮组件
	closeButton := widget.NewButton("关闭", func() {
		myApp.Quit()
	})

	//第一个参数，每行几个？
	grid := container.New(layout.NewGridLayout(1), resultTable...)

	// 创建一个容器并添加组件
	content := container.NewVBox(
		showTime,
		helloLabel,
		base64Input,
		parseButton,
		closeButton,
		grid,
	)

	// 将容器添加到窗口
	myWindow.SetContent(content)

	// 显示窗口
	myWindow.ShowAndRun()
}

func freshTimeSeconds() *widget.Label {
	//填充当前时间
	nowTime := widget.NewLabel(time.Now().Format(DateTime))
	//异步线程更新时间
	go func() {
		for range time.Tick(time.Second) {
			nowTime.SetText(time.Now().Format(DateTime))
		}
	}()
	return nowTime
}

func matchSignAlgFromOid(signAlgOid string) string {

	switch signAlgOid {
	case x509.SM3WithSM2:
		return "SM3WithSM2"
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA1WithRSA:
		return "SHA1WithRSA"
	default:
		return signAlgOid
	}
}

func StringIsEmpty(data string) bool {
	if data == "" || len(data) == 0 {
		return true
	}
	return false

}
