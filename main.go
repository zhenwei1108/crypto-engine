package main

import (
	"crypto-engine/src/util"
	"crypto-engine/src/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
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

// MIICETCCAbWgAwIBAgINKl81oFaaablKOp0YTjAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDgxMzIwMTkzNFoXDTIwMTAyNDE1NTk1OVowHjELMAkGA1UEBgwCQ04xDzANBgNVBAMMBuWGr+i9rDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIF97Sqq0Rv616L2PjFP3xt16QGJLmi+W8Ht+NLHiXntgUey0Nz+ZVnSUKUMzkKuGTikY3h2v7la20b6lpKo8WjgZIwgY8wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSxiaS6z4Uguz3MepS2zblkuAF/LTAfBgNVHSMEGDAWgBTMZyRCGsP4rSes0vLlhIEf6cUvrjBABgNVHSAEOTA3MDUGCSqBHIbvMgICAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAMBggqgRzPVQGDdQUAA0gAMEUCIG6n6PG0BOK1EdFcvetQlC+9QhpsTuTui2wkeqWiPKYWAiEAvqR8Z+tSiYR5DIs7SyHJPWZ+sa8brtQL/1jURvHGxU8=
// MIIEfjCCA2agAwIBAgIQefIDuSADkosPySFwsKcsjDANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJDTjEmMCQGA1UECgwdQkVJSklORyBDRVJUSUZJQ0FURSBBVVRIT1JJVFkxGTAXBgNVBAMMEEJKQ0EgRG9jU2lnbiBDQTMwHhcNMjAxMjA3MDc1MDAwWhcNMjExMjA3MDc1MDAwWjBIMQswCQYDVQQGEwJDTjElMCMGA1UECwwcYmI1Tndlbk5kYVg2ZkhNd1VKUlkvQTFOVDcwPTESMBAGA1UEAwwJ5p2O5Li96ZyeMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzeiCgLXKDzzBsLLHedJKG11m6SotdlynexHe8cI1TmWa3ODerwBHukr5ZkJft3seIQqFHi6xVlNgfOHO5WNgCKpvg/HxRoQshwLDYgeH5KcpH67dv1dl6urqwvwzSE5gmJo1+OGqAl9yeG9X76zkueZUd4v3RrVOoofbTlSBkWoigXH/0mpu/vgxhDRzmksNQvZ+Ay2jisdshpZovH6a+ABYMYMYo4U1o6BfvHBKEPo20TDJ/t0KlVRoHkgiMvtO8NOI5d0cxea5RaOCDT10CGHheqieMibUQnCkB6Yi01aoDQxtG8TshO7uGWoMzqPPs+u44Ym1s2LH51fvTS6bHQIDAQABo4IBWjCCAVYwcQYIKwYBBQUHAQEEZTBjMEAGCCsGAQUFBzAChjRodHRwOi8vcmVwby5iamNhLmNuL2dsb2JhbC9jZXJ0L0JKQ0FfRG9jU2lnbl9DQTMuY3J0MB8GCCsGAQUFBzABhhNodHRwOi8vb2NzcC5iamNhLmNuMB0GA1UdDgQWBBQh7RHFVos8ievEiiAvASMjEmqw+zAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFCA6epfxEmaXv3PW5YXPR9M0GLwyMD0GA1UdIAQ2MDQwMgYJKoEchu8yAgIWMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vd3d3LmJqY2EuY24vQ1BTMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9yZXBvLmJqY2EuY24vZ2xvYmFsL2NybC9CSkNBX0RvY1NpZ25fQ0EzLmNybDAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQELBQADggEBAF5apKpbT9EG+gJP82LKKwbW9/jUJ/9tZEzPKfX4Uqs7YB3DCnM78qLBKvHByP9bUv2L7Yd6ncv9FORJqw6KEJiNz6/wXcNsNN/MYj8tZNonMyTW+tGkoRR0AqPWHZ1Cq+M0LFYuL8uwkMXDPZiHrrwtwNrr5cSsrYiamDyoZAe6MRzBiU9WgpzGWbMPu+IRoYye04Cq/yEVBsHLnUR24wehUVgPJb68tR7j3M3Yc3gSbTb9ymFFfETxaf2qDUelnr7CqhM/Ddj77dnZ86ZUGi95l7SDeEQW56EL9Og4TnLuL7A0tOPZhADwY5mgiQbLiMziO7szirh8wK8R5njJ9gI=
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
	var content *fyne.Container
	//输入
	base64Input := &widget.Entry{MultiLine: true, Wrapping: fyne.TextWrapWord}

	//input.Wrapping = fyne.text
	//输入Base64的X.509证书
	base64Input.SetPlaceHolder("MIICETCCAbWgAwIBAgINKl81oFaaablKOp0YTjAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDgxMzIwMTkzNFoXDTIwMTAyNDE1NTk1OVowHjELMAkGA1UEBgwCQ04xDzANBgNVBAMMBuWGr+i9rDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIF97Sqq0Rv616L2PjFP3xt16QGJLmi+W8Ht+NLHiXntgUey0Nz+ZVnSUKUMzkKuGTikY3h2v7la20b6lpKo8WjgZIwgY8wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSxiaS6z4Uguz3MepS2zblkuAF/LTAfBgNVHSMEGDAWgBTMZyRCGsP4rSes0vLlhIEf6cUvrjBABgNVHSAEOTA3MDUGCSqBHIbvMgICAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAMBggqgRzPVQGDdQUAA0gAMEUCIG6n6PG0BOK1EdFcvetQlC+9QhpsTuTui2wkeqWiPKYWAiEAvqR8Z+tSiYR5DIs7SyHJPWZ+sa8brtQL/1jURvHGxU8=")
	base64Input.Text = "MIICETCCAbWgAwIBAgINKl81oFaaablKOp0YTjAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDgxMzIwMTkzNFoXDTIwMTAyNDE1NTk1OVowHjELMAkGA1UEBgwCQ04xDzANBgNVBAMMBuWGr+i9rDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIF97Sqq0Rv616L2PjFP3xt16QGJLmi+W8Ht+NLHiXntgUey0Nz+ZVnSUKUMzkKuGTikY3h2v7la20b6lpKo8WjgZIwgY8wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSxiaS6z4Uguz3MepS2zblkuAF/LTAfBgNVHSMEGDAWgBTMZyRCGsP4rSes0vLlhIEf6cUvrjBABgNVHSAEOTA3MDUGCSqBHIbvMgICAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAMBggqgRzPVQGDdQUAA0gAMEUCIG6n6PG0BOK1EdFcvetQlC+9QhpsTuTui2wkeqWiPKYWAiEAvqR8Z+tSiYR5DIs7SyHJPWZ+sa8brtQL/1jURvHGxU8="

	hexInput := &widget.Entry{MultiLine: true, Wrapping: fyne.TextWrapWord}
	hexInput.SetPlaceHolder("输入Hex的X.509证书")

	//定义一个切片，用于构造表格，key-value
	resultTable := []fyne.CanvasObject{}
	//签名算法标识符
	signAlgText := canvas.NewText("", color.Black)
	//颁发者
	issueText := canvas.NewText("", color.Black)
	issueText.TextStyle = fyne.TextStyle{Italic: true, Bold: true}
	subjectText := canvas.NewText("", color.Black)
	//有效期
	validityText := canvas.NewText("", color.Black)

	serNoText := canvas.NewText("", color.Black)

	//展示信息排序
	resultTable = append(resultTable, serNoText, signAlgText, issueText, subjectText, validityText)

	var certBytes []byte
	encodeButton := widget.NewButton("Hex/Base转换", func() {
		certBytes = getInput(base64Input, hexInput)
	})
	parseCertButton := widget.NewButton("解析证书", func() {
		//输入为空，则什么都不处理
		if util.BytesIsEmpty(certBytes) {
			certBytes = getInput(base64Input, hexInput)
			if util.BytesIsEmpty(certBytes) {
				return
			}
		}
		var certificate x509.Certificate
		_, err := asn1.Unmarshal(certBytes, &certificate)
		if err != nil {
			signAlgText.Text = err.Error()
		}
		signAlgText.Text = "签名算法: " + matchSignAlgFromOid(certificate.SignatureAlgorithm.Algorithm.String()) //非必填项可以跳过
		issueText.Text = "颁发者: " + certificate.TbsCertificate.Issuer.String()
		validityText.Text = "有效期: " + certificate.TbsCertificate.Validity.NotBefore.Format(DateTime) + " 至 " + certificate.TbsCertificate.Validity.NotAfter.Format(DateTime)
		serNoText.Text = "证书序列号: " + strings.ToUpper(certificate.TbsCertificate.SerialNumber.Text(16))
		subjectText.Text = "使用者: " + certificate.TbsCertificate.Subject.String()

	})

	var grid *fyne.Container
	//第一个参数，每行几个？
	grid = container.New(layout.NewGridLayout(1), resultTable...)
	// 创建一个按钮组件
	closeButton := widget.NewButton("关闭", func() {
		myApp.Quit()
	})

	allButton := container.New(layout.NewGridLayout(2), encodeButton, parseCertButton)
	//grid.Hide()

	// 创建一个容器并添加组件
	content = container.NewVBox(
		showTime,
		helloLabel,
		base64Input,
		hexInput,
		allButton,
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

func getInput(base64Input *widget.Entry, hexInput *widget.Entry) (certBytes []byte) {
	base64InputString := strings.ReplaceAll(base64Input.Text, " ", "")
	hexInputString := strings.ReplaceAll(hexInput.Text, " ", "")
	if util.StringIsEmpty(base64InputString) {
		certBytes, _ = hex.DecodeString(hexInputString)
		base64Input.Text = base64.StdEncoding.EncodeToString(certBytes)
	}
	if util.StringIsEmpty(hexInputString) {
		certBytes, _ = base64.StdEncoding.DecodeString(base64InputString)
		hexInput.SetText(hex.EncodeToString(certBytes))
	}
	return certBytes
}
