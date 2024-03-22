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
	base64Input.SetPlaceHolder("Input Base64 Data here")
	base64Input.Text = "MIICETCCAbWgAwIBAgINKl81oFaaablKOp0YTjAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDgxMzIwMTkzNFoXDTIwMTAyNDE1NTk1OVowHjELMAkGA1UEBgwCQ04xDzANBgNVBAMMBuWGr+i9rDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIF97Sqq0Rv616L2PjFP3xt16QGJLmi+W8Ht+NLHiXntgUey0Nz+ZVnSUKUMzkKuGTikY3h2v7la20b6lpKo8WjgZIwgY8wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSxiaS6z4Uguz3MepS2zblkuAF/LTAfBgNVHSMEGDAWgBTMZyRCGsP4rSes0vLlhIEf6cUvrjBABgNVHSAEOTA3MDUGCSqBHIbvMgICAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAMBggqgRzPVQGDdQUAA0gAMEUCIG6n6PG0BOK1EdFcvetQlC+9QhpsTuTui2wkeqWiPKYWAiEAvqR8Z+tSiYR5DIs7SyHJPWZ+sa8brtQL/1jURvHGxU8="
	base64Input.Text = "MIIBVzCB/aADAgECAgMB4kAwCgYIKoEcz1UBg3UwKTEYMAkGA1UEBhMCQ04wCwYDVQQGEwRUZXN0MQ0wCwYDVQQDEwRhZHNmMCYXETI0MDMyMDIyMjQzNiswODAwFxEyNjAzMjAyMjI0MzYrMDgwMDAhMQswCQYDVQQGEwJDTjESMBAGA1UEAxMJVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAET2aKBJNS1+09pI28CkeEGvBLQXER9+BFMEEvr8BJ4HgrGrM/ha9wU1V3SpIGJv/3WeslARuwCCEZOooRDNfOLqMUMBIwEAYDVR0TBAl0ZXN0IGNlcnQwCgYIKoEcz1UBg3UDSQAwRgIhAJdNx0/nRoczKdotf3X1hzyRtSrN3Vf55BsNmveCpIf3AiEAl03HT+dGhzMp2i1/dfWHPJG1Ks3dV/nkGw2a94Kkh/c="

	hexInput := &widget.Entry{MultiLine: true, Wrapping: fyne.TextWrapWord}
	hexInput.SetPlaceHolder("Input Hex Data here")
	var grid *fyne.Container
	var certBytes []byte
	encodeButton := widget.NewButton("Hex/Base转换", func() {
		//清空上次的数据
		content.Remove(grid)
		getInputAboutCert(base64Input, hexInput)
	})

	parseCertButton := widget.NewButton("解析证书", func() {
		//定义一个切片，用于构造表格，key-value
		resultTable := []fyne.CanvasObject{}
		//清空上次的数据
		content.Remove(grid)

		//输入为空，则什么都不处理
		if util.BytesIsEmpty(certBytes) {
			certBytes = getInputAboutCert(base64Input, hexInput)
			if util.BytesIsEmpty(certBytes) {
				return
			}
		}
		var certificate x509.Certificate
		_, err := asn1.Unmarshal(certBytes, &certificate)

		//签名算法标识符
		signAlgText := canvas.NewText("", color.Black)
		//颁发者
		issueText := canvas.NewText("", color.Black)
		issueText.TextStyle = fyne.TextStyle{Italic: true, Bold: true}
		subjectText := canvas.NewText("", color.Black)
		//有效期
		validityText := canvas.NewText("", color.Black)

		serNoText := canvas.NewText("", color.Black)
		pubKeyAlgText := canvas.NewText("", color.Black)
		pubKeyText := canvas.NewText("", color.Black)
		issueIdText := canvas.NewText("", color.Black)
		subjectIdText := canvas.NewText("", color.Black)
		if err != nil {
			signAlgText.Text = err.Error()
		}
		signAlgText.Text = "签名算法: " + matchSignAlgFromOid(certificate.SignatureAlgorithm.Algorithm.String()) //非必填项可以跳过

		issueText.Text = "颁发者: " + certificate.TbsCertificate.Issuer.ToString()
		validityText.Text = "有效期: " + certificate.TbsCertificate.Validity.NotBefore.Format(DateTime) + " 至 " + certificate.TbsCertificate.Validity.NotAfter.Format(DateTime)
		serNoText.Text = "证书序列号: " + strings.ToUpper(certificate.TbsCertificate.SerialNumber.Text(16))
		subjectText.Text = "使用者: " + certificate.TbsCertificate.Subject.ToString()
		info := certificate.TbsCertificate.SubjectPublicKeyInfo
		//ecc 1.2.840.10045.2.1
		pubKeyAlgText.Text = "公钥算法: " + matchPublicKeyAlgFromOid(info.Algorithm.Algorithm.String())
		pubKeyText.Text = "公钥: " + strings.ToUpper(hex.EncodeToString(info.SubjectPublicKey.Bytes))
		//optional
		issuerIdBytes := certificate.TbsCertificate.IssuerUniqueID.Bytes
		//展示信息排序
		resultTable = append(resultTable, serNoText, signAlgText, issueText, subjectText, validityText, pubKeyAlgText, pubKeyText, issueIdText, subjectIdText)
		if issuerIdBytes != nil {
			issueIdText.Text = "颁发者标识符: " + hex.EncodeToString(issuerIdBytes)
			resultTable = append(resultTable, issueIdText)
		}

		subjectIdBytes := certificate.TbsCertificate.SubjectUniqueID.Bytes
		if subjectIdBytes != nil {
			subjectIdText.Text = "使用者标识符: " + hex.EncodeToString(subjectIdBytes)
			resultTable = append(resultTable, subjectIdText)
		}

		//补充证书解析结果，并刷新
		grid = container.New(layout.NewGridLayout(1), resultTable...)
		content.Add(grid)
		content.Refresh()
	})

	base64Input.OnChanged = func(data string) {
		if util.StringIsEmpty(data) && util.StringIsEmpty(hexInput.Text) {
			encodeButton.Hide()
			parseCertButton.Hide()
		} else {
			encodeButton.Show()
			parseCertButton.Show()
		}
	}

	hexInput.OnChanged = func(data string) {
		if util.StringIsEmpty(data) && util.StringIsEmpty(base64Input.Text) {
			encodeButton.Hide()
			parseCertButton.Hide()
		} else {
			encodeButton.Show()
			parseCertButton.Show()
		}
	}

	// 创建一个关闭按钮
	//closeButton := widget.NewButton("关闭", func() {
	//	myApp.Quit()
	//})
	//对所有按钮进行表格化
	allButton := container.New(layout.NewGridLayout(2), encodeButton, parseCertButton)
	//grid.Hide()

	// 创建一个容器并添加组件
	content = container.NewVBox(
		showTime,
		helloLabel,
		base64Input,
		hexInput,
		allButton,
		//closeButton,
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

func matchPublicKeyAlgFromOid(oid string) string {
	switch oid {
	case x509.ECCOid:
		return "ECC"
	case x509.SM2Oid:
		return "SM2"
	case x509.RSAOid:
		return "RSA"
	default:
		return ""
	}
}

// 匹配签名算法
func matchSignAlgFromOid(signAlgOid string) string {

	switch signAlgOid {
	case x509.SM3WithSM2Oid:
		return "SM3WithSM2"
	case x509.SHA256WithRSAOid:
		return "SHA256WithRSA"
	case x509.SHA1WithRSAOid:
		return "SHA1WithRSA"
	default:
		return signAlgOid
	}
}

// 获取输入的证书信息
func getInputAboutCert(base64Input *widget.Entry, hexInput *widget.Entry) (certBytes []byte) {
	var base64InputString, hexInputString string
	base64InputString = strings.ReplaceAll(base64Input.Text, " ", "")
	hexInputString = strings.ReplaceAll(hexInput.Text, " ", "")
	if util.StringIsEmpty(base64InputString) && util.StringIsEmpty(hexInputString) {
		return nil
	}
	if util.StringIsEmpty(base64InputString) {
		certBytes, _ = hex.DecodeString(hexInputString)
		base64Input.Text = base64.StdEncoding.EncodeToString(certBytes)
		base64Input.Refresh()
	} else {
		certBytes, _ = base64.StdEncoding.DecodeString(base64InputString)
		hexInput.SetText(hex.EncodeToString(certBytes))
		hexInput.Refresh()
	}
	return certBytes
}
