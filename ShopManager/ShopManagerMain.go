package main

import (
	smdp "ShopManagerDataProc"
	"bytes"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
)

type users struct {
	Pwd         string `form:"pwd" json:"pwd" binding:"required"`
	Name        string `form:"name" json:"name" binding:"required"`
	NickName    string `form:"nickname" json:"nickname" binding:"required"`
	Email       string `form:"email" json:"email" binding:"required"`
	Gender      string `form:"gender" json:"gender" binding:"required"`
	Birthday    string `form:"birthday" json:"birthday" binding:"required"`
	Phone       string `form:"phone" json:"phone" binding:"required"`
	OriginalPwd string `form:"originalPwd" json:"originalPwd" binding:"required"`
}
type items struct {
	Email       string `form:"email" json:"email" binding:"required"`
	ItemName    string `form:"item_name" json:"item_name" binding:"required"`
	Price       int    `form:"price" json:"price" binding:"required"`
	Description string `form:"description" json:"description" binding:"required"`
}

type GcGame []struct {
	GameName string `form:"gamename" json:"gamename" binding:"required"`
	GameType string `form:"gametype" json:"gametype" binding:"required"`
}

type GcWeb struct {
	UserID      string `form:"user_id" json:"user_id" binding:"required"`
	GameName    string `form:"game_name" json:"game_name" binding:"required"`
	ServerName  string `form:"server_name" json:"server_name" binding:"required"`
	Fb_ID       string `form:"fb_id" json:"fb_id" binding:"required"`
	Line_ID     string `form:"line_id" json:"line_id" binding:"required"`
	Youtube     string `form:"youtube" json:"youtube" binding:"required"`
	Twitch_ID   string `form:"twitch_id" json:"twitch_id" binding:"required"`
	Ig_ID       string `form:"ig_id" json:"ig_id" binding:"required"`
	Gpx_ID      string `form:"gpx_id" json:"gpx_id" binding:"required"`
	Discord_ID  string `form:"discord_id" json:"discord_id" binding:"required"`
	Details     string `form:"details" json:"details" binding:"required"`
	Public_Key  string `form:"public_key" json:"public_key" binding:"required"`
	Private_Key string `form:"private_key" json:"private_key" binding:"required"`
	Email       string `form:"email" json:"email" binding:"required"`
	Link        string `form:"link" json:"link" binding:"required"`
}

const IMGUR_TOKEN = "6bf07ca4e27fc6e056ecd0eea71bf78360a9b0fc"

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	v1 := router.Group("v1")
	gc := router.Group("gc")

	//使用者相關
	router.LoadHTMLGlob("/Users/kuanchengchou/go/src/ShopManager/GameCard/*.html")
	gc.Static("/plugin", "/Users/kuanchengchou/go/src/ShopManager/GameCard/plugin")
	gc.Static("/js", "/Users/kuanchengchou/go/src/ShopManager/GameCard/js")
	gc.Static("/img", "/Users/kuanchengchou/go/src/ShopManager/GameCard/img")
	gc.Static("/css", "/Users/kuanchengchou/go/src/ShopManager/GameCard/css")
	v1.POST("/User/Register", Register)
	v1.POST("/User/Login", Login)
	v1.PATCH("/User/ChangePwd", UpdatePassword)
	v1.PATCH("/User/UpdateInfo", UserinfoModify)
	v1.POST("/User/Forget", ForgetPassword)
	v1.GET("/User/GetNewPassword", NewPassword)
	v1.GET("/User/Verify", AccountVerify)
	v1.DELETE("/User/DeleteUser", DeleteUser)
	//商品相關
	v1.POST("/Menu/Add", MenuAdd)
	v1.GET("/Menu/List", MenuList)
	v1.PATCH("/Menu/Update", MenuModify)
	//其他：GameCard
	gc.GET("/web/:mode", WebLoad)
	//刪除名片
	gc.POST("/api/Delete", DeleteCard)
	//送出編輯
	gc.POST("/api/PreEdit", PreEditCard)
	//送出已編輯資料
	gc.PATCH("/api/Edit", SendEdit)
	//建立新名片
	gc.POST("/api/CreateData", GameCardCreate)
	gc.POST("/api/SendMail", SendMail)
	router.Run()
}

////////////Struct Init///////////
var userInfo users
var gcInfo GcWeb
var gcGame GcGame

////////////GameCard/////////////
func WebLoad(c *gin.Context) {
	loadPages := c.Param("mode")
	switch loadPages {
	case "Index":
		c.HTML(200, "Index.html", gin.H{"Title": "HOME"})
		break
	case "Create":
		c.HTML(200, "CreateCard.html", gin.H{"Title": "CREATE"})
		break
	case "View":
		GetInfo(c, "ViewCard.html")
		break
	case "Edit":
		GetInfo(c, "EditCard.html")
		break
	}
}
func GetInfo(c *gin.Context, htmlFile string) {
	publicKey := c.Query("public_key")
	if publicKey != "" {
		gameInfo, _ := smdp.GetGameCardInfo(publicKey)
		if gameInfo != nil {
			c.HTML(200, htmlFile, gin.H{"publickey": gameInfo["publickey"], "gamename": gameInfo["gamename"],
				"userid": gameInfo["userid"], "photourl": gameInfo["photourl"], "fbid": gameInfo["fbid"], "lineid": gameInfo["lineid"],
				"youtube": gameInfo["youtube"], "twitchid": gameInfo["twitchid"], "ig": gameInfo["ig"], "gamplexid": gameInfo["gamplex"],
				"server": gameInfo["server"], "details": gameInfo["details"], "discordid": gameInfo["discordid"]})
		} else {
			c.String(http.StatusBadRequest, "%s", "公鑰錯誤。")
		}
	} else {
		c.String(http.StatusBadRequest, "%s", "公鑰不得為空。")
	}
}

func GameCardCreate(c *gin.Context) {
	HeaderSet(c)
	if c.ShouldBind(&gcInfo) != nil {
		if gcInfo.UserID == "" || gcInfo.GameName == "" || gcInfo.Details == "" {
			c.JSON(400, gin.H{"CARD_CREATE": "Id,Game name,Details its must."})
		} else {
			fmt.Printf("Userid: %s , Gamename: %s , Details: %s \n", gcInfo.UserID, gcInfo.GameName, gcInfo.Details)
			success, link := GcimgUpload(c)
			if success == true {
				publicKey, privateKey := smdp.GameCardInsert(gcInfo.GameName, gcInfo.UserID, gcInfo.ServerName, gcInfo.Line_ID, gcInfo.Youtube, gcInfo.Twitch_ID, gcInfo.Ig_ID, gcInfo.Fb_ID, gcInfo.Gpx_ID, gcInfo.Discord_ID, gcInfo.Details, link)
				gamecardLink := "https://manager-shop.xyz/gc/web/View?public_key=" + publicKey
				c.JSON(200, gin.H{"GamecardLink": gamecardLink, "PrivateKey": privateKey})
			} else {
				c.JSON(200, gin.H{"CARD_CREATE": link})
			}
		}
	} else {
		c.JSON(400, gin.H{"CARD_CREATE": "FAIL"})
	}
}

func DeleteCard(c *gin.Context) {
	var resp string
	HeaderSet(c)
	if gcInfo.Public_Key == "" || gcInfo.Private_Key == "" {
		c.JSON(200, gin.H{"EDIT": "FAIL"})
	} else {
		resp = smdp.DeleteCard(gcInfo.Public_Key, gcInfo.Private_Key)
		c.JSON(200, gin.H{"EDIT": resp})
	}
}

func PreEditCard(c *gin.Context) {
	var resp string
	HeaderSet(c)
	if c.ShouldBind(&gcInfo) != nil {
		if gcInfo.Public_Key == "" {
			c.JSON(http.StatusBadRequest, gin.H{"resp": "PUBLIC_KEY_ERR"})
		} else {
			resp = smdp.PreEditCard(gcInfo.Public_Key)
			if resp != "FAIL" {
				c.JSON(200, gin.H{"resp": resp})
				println(resp)

			} else {
				c.JSON(400, gin.H{"resp": "FAIL"})
			}
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"resp": "PUBLIC_KEY_ERR"})
	}
}

func SendEdit(c *gin.Context) {
	HeaderSet(c)
	if c.ShouldBind(&gcInfo) != nil {
		if gcInfo.Public_Key == "" || gcInfo.Private_Key == "" {
			c.JSON(http.StatusBadRequest, gin.H{"resp": "BAD_REQUEST"})
		} else {
			success, link := GcimgUpload(c)
			if success == true {
				resp := smdp.EditCard(gcInfo.GameName, gcInfo.UserID, gcInfo.ServerName, gcInfo.Line_ID, gcInfo.Youtube, gcInfo.Twitch_ID, gcInfo.Ig_ID, gcInfo.Fb_ID, gcInfo.Gpx_ID, gcInfo.Discord_ID, gcInfo.Details, link, gcInfo.Public_Key, gcInfo.Private_Key)
				c.JSON(http.StatusOK, gin.H{"resp": resp})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"resp": link})
			}
		}
	}
}
func GcimgUpload(c *gin.Context) (bool, string) {
	HeaderSet(c)
	fileSavePath := "/Users/kuanchengchou/Desktop/GameCard/UploadImage/"
	file, _ := c.FormFile("IMG")
	if file == nil {
		return true, ""
	} else {
		if file.Size < 1.5*1024*1024 {
			fileName := file.Filename
			if strings.Contains(fileName, ".jpg") || strings.Contains(fileName, ".jpeg") || strings.Contains(fileName, ".png") || strings.Contains(fileName, ".gif") {
				fileOpen, _ := file.Open()
				defer fileOpen.Close()
				if err := c.SaveUploadedFile(file, fileSavePath+fileName); err != nil {
					log.Fatal(err.Error())
				}
				return true, fileSavePath + fileName
			} else {
				return false, "FORMAT_ERR"
			}

		} else {
			return false, "FILE_SIZE_TOO_LARGE"
		}
	}
	return true, ""
}
func SendMail(c *gin.Context) {
	HeaderSet(c)
	if c.ShouldBind(&gcInfo) != nil {
		if gcInfo.Email == "" || gcInfo.Public_Key == "" || gcInfo.Private_Key == "" {
			c.JSON(http.StatusBadRequest, gin.H{"resp": "SEND_ERR"})
		} else {
			resp := smdp.GameCardEmail(gcInfo.Email, gcInfo.Public_Key, gcInfo.Private_Key)
            c.JSON(200,gin.H{"resp":resp})
		}
	}
}
func HeaderSet(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Headers", "Content-Type,origin")
	c.Header("Access-Control-Allow-Methods", "POST,GET,OPTIONS")
}

////////////GameCard/////////////
///////////V1-使用者相關/////////////
func Register(c *gin.Context) {
	//註冊使用者
	conType := c.GetHeader("content-type")
	fmt.Printf("Content-Type: %s", conType)
	if c.ShouldBind(&userInfo) != nil {
		if userInfo.Email == "" || userInfo.Pwd == "" || userInfo.Name == "" || userInfo.NickName == "" {
			c.JSON(http.StatusOK, gin.H{"REGISTER": "信箱,密碼,姓名,暱稱為必填"})
		} else {
			response := smdp.UserInfoRegister(userInfo.Email, userInfo.Pwd, userInfo.Birthday, userInfo.Name, userInfo.NickName)
			if strings.Contains(response, "PRIMARY") {
				c.JSON(http.StatusOK, gin.H{"REGISTER": "帳號重複"})
			} else {
				c.JSON(http.StatusOK, gin.H{"REGISTER": "SUCCESS"})
			}
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"REGISTER": "BAD_REQUEST"})

	}
}
func UserinfoModify(c *gin.Context) {
	//補完會員資料
	file, err := c.FormFile("FILE")
	if err != nil {
		panic(err)
	}
	fileOpen, err := file.Open()
	if err != nil {
		panic(err)
	}
	defer fileOpen.Close()
	println(file.Filename)
	if c.ShouldBind(&userInfo) != nil {
		if userInfo.Email != "" {
			link := upload(fileOpen, IMGUR_TOKEN)
			result := smdp.UserInfoUpdate(userInfo.Email, userInfo.Phone, link, userInfo.Gender, userInfo.Birthday, userInfo.Name, userInfo.NickName)
			c.JSON(http.StatusOK, gin.H{"Upload_Info": result})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"Upload_Info": "使用者信箱為空"})

		}
	}
}
func Login(c *gin.Context) {
	//使用者帳號登入//
	if c.ShouldBind(&userInfo) != nil {
		if userInfo.Email == "" || userInfo.Pwd == "" {
			c.JSON(http.StatusOK, gin.H{"LOGIN": "帳號或密碼為空"})
		} else {
			response := smdp.Login(userInfo.Email, userInfo.Pwd)
			c.JSON(http.StatusOK, gin.H{"LOGIN": response})
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"LOGIN": "BAD_REQUEST"})
	}
}
func UpdatePassword(c *gin.Context) {
	//修改密碼//
	if c.ShouldBind(&userInfo) != nil {
		if userInfo.Email == "" || userInfo.OriginalPwd == "" || userInfo.Pwd == "" {
			c.JSON(http.StatusOK, gin.H{"Password_Update": "帳號密碼不得空白"})
		} else {
			response := smdp.PasswordChange(userInfo.Email, userInfo.OriginalPwd, userInfo.Pwd)
			c.JSON(http.StatusOK, gin.H{"Password_Update": response})
		}
	}
}
func ForgetPassword(c *gin.Context) {
	//忘記密碼//
	if c.ShouldBind(&userInfo) != nil {
		if userInfo.Email == "" {
			c.JSON(http.StatusOK, gin.H{"SENDMAIL_TO": "請填入E-mail"})
		} else {
			response := smdp.PasswordForget(userInfo.Email)
			c.JSON(http.StatusOK, gin.H{"SENDMAIL_TO": response})
		}
	}
}
func DeleteUser(c *gin.Context) {
	//註銷使用者//
	if c.ShouldBind(&userInfo) != nil {
		if userInfo.Email == "" || userInfo.Pwd == "" {
			c.JSON(http.StatusOK, gin.H{"User_Delete": "帳號密碼不得空白"})
		} else {
			response := smdp.DeleteUser(userInfo.Email, userInfo.Pwd)
			c.JSON(http.StatusOK, gin.H{"User_Delete": response})
		}
	}
}
func NewPassword(c *gin.Context) {
	uMail := c.Request.URL.Query().Get("Umail")
	key := c.Request.URL.Query().Get("Key")
	if uMail == "" || key == "" {
		c.String(200, "%s", "錯誤的請求")
	} else {
		response := smdp.SendRandomPwd(uMail, key)
		if response == "SUCCESS" {
			c.String(200, "已將臨時密碼寄至：%s ,若無收到請稍後再次申請。", uMail)
		} else {
			c.String(200, "%s", "發生錯誤。")
		}
	}
}
func AccountVerify(c *gin.Context) {
	uMail := c.Request.URL.Query().Get("Umail")
	key := c.Request.URL.Query().Get("Key")
	if uMail == "" || key == "" {
		c.String(200, "%s", "錯誤的請求")
	} else {
		response := smdp.AccountVerify(uMail, key)
		if response == "SUCCESS" {
			c.String(200, "%s", "感謝您的註冊。")
		} else {
			c.String(200, "%s", "發生錯誤。")
		}
	}
}

//////////////V1-使用者相關/////////////
//////////////V1-品項相關//////////////
func MenuAdd(c *gin.Context) {
	//品項新增//

}
func MenuList(c *gin.Context) {
	//品項讀取//
}
func MenuModify(c *gin.Context) {
	//品項修改//
}

//////////////V1-品項相關//////////////
//////////////V1-其他/////////////////

//////////////V1-其他/////////////////
func upload(image io.Reader, token string) string {
	APIURL := "https://api.imgur.com/3/image"
	var buf = new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	part, _ := writer.CreateFormFile("image", "dont care about name")
	io.Copy(part, image)
	writer.Close()
	req, _ := http.NewRequest("POST", APIURL, buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{}
	res, _ := client.Do(req)
	defer res.Body.Close()
	var link string
	b, _ := ioutil.ReadAll(res.Body)
	success := gjson.Get(string(b), "success")
	if strings.Contains(success.Str, "true") {
		link = gjson.Get(string(b), "data.link").Str
		fmt.Printf("Link: %s", link)
	}
	return link
}
