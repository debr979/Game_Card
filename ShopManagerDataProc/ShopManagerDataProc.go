package ShopManagerDataProc

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"math/rand"
	"net/smtp"
	"strings"
	"time"
)

type GcWeb struct {
	UserID     string `form:"user_id" json:"user_id" binding:"required"`
	GameName   string `form:"game_name" json:"game_name" binding:"required"`
	ServerName string `form:"server_name" json:"server_name" binding:"required"`
	Fb_ID      string `form:"fb_id" json:"fb_id" binding:"required"`
	Line_ID    string `form:"line_id" json:"line_id" binding:"required"`
	Youtube    string `form:"youtube" json:"youtube" binding:"required"`
	Twitch_ID  string `form:"twitch_id" json:"twitch_id" binding:"required"`
	Ig_ID      string `form:"ig_id" json:"ig_id" binding:"required"`
	Gpx_ID     string `form:"gpx_id" json:"gpx_id" binding:"required"`
	Discord_ID string `form:"discord_id" json:"discord_id" binding:"required"`
	Details    string `form:"details" json:"details" binding:"required"`
	Public_Key string `form:"public_key" json:"public_key" binding:"required"`
	PhotoURL   string `form:"photourl" json:"photourl" binding:"required"`
}

const (
	db_userName     = "*"
	db_password     = "*"
	db_host         = "*"
	dbName_RealTime = "RealTimeCall"
	dbName_GameCard = "GameBCard"
)

var connectionString_RealTime = fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?allowNativePasswords=true", db_userName, db_password, db_host, dbName_RealTime)
var connectionString_GameCard = fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?allowNativePasswords=true", db_userName, db_password, db_host, dbName_GameCard)

func shaProc(pwd string) string {
	//密碼轉成sha256
	hash := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(hash[:])
}
func UserInfoRegister(email string, password string, birthday string, userName string, nickName string) string {
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	//寫進主表
	userMainTableQueryString := "INSERT INTO RealTimeCall_Userinfo(EMail,Birthday,UserName,DisplayName,RegisterTime,Is_Active) values (?,?,?,?,?,0)"
	//寫進帳號驗證表
	loginTableQueryString := "INSERT INTO RealTimeCall_Userinfo_Pwd(EMail,Password,SecureKey) VALUES (?,?,?)"
	time := time.Now()
	tx, err := db.Begin()
	if err != nil {
		return err.Error()
	}
	defer tx.Rollback()
	//寫入主表資料
	_, err = tx.Exec(userMainTableQueryString, email, birthday, userName, nickName, time.Format("2006-01-02 15:04:05"))
	if err != nil {
		return err.Error()
	}
	//寫入登入表資料
	rndCode := RndCodeCreator(15)
	_, err = tx.Exec(loginTableQueryString, email, shaProc(password), rndCode)
	if err != nil {
		return err.Error()
	}
	err = tx.Commit()
	if err != nil {
		return err.Error()
	} else {
		verifyURL := "請點擊下列連結，以進行驗證 \n\n " + "https://www.manager-shop.xyz/v1/User/Verify?Umail=" + email + "&" + "Key=" + rndCode
		MailSend(email, "[ShopManager]Verify Email", verifyURL)
		return "SUCCESS"
	}
}
func Login(loginMail string, password string) string {
	/* input Mail and password
	   then output affected rows count.
	*/
	shaPassword := shaProc(password)
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	time := time.Now().Format("2006-01-02 15:04:05")
	sqlcmd, err := db.Prepare("UPDATE RealTimeCall_Userinfo_Pwd SET Lastlogin=? WHERE EMail=? AND Password=?")
	if err != nil {
		return err.Error()
	}
	res, err := sqlcmd.Exec(time, loginMail, shaPassword)
	if err != nil {
		return err.Error()
	}
	affectCount, err := res.RowsAffected()
	if err != nil {
		return err.Error()
	}
	if affectCount > 0 {
		return "SUCCESS"
	} else {
		return "FAIL"
	}
}
func AccountVerify(email string, key string) string {
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	rows, err := db.Query("SELECT EMail FROM RealTimeCall_Userinfo_Pwd WHERE EMail=? AND SecureKey =?", email, key)
	if err != nil {
		return err.Error()
	}
	var preVerifyMail string
	var updateActive string
	for rows.Next() {
		if err := rows.Scan(&preVerifyMail); err != nil {
			return err.Error()
		}
		updateActive = activeAccount(preVerifyMail)
	}
	return updateActive
}
func activeAccount(email string) string {
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	updateActive := "UPDATE RealTimeCall_Userinfo SET Is_Active=? WHERE EMail=?"
	updateKey := "UPDATE RealTimeCall_Userinfo_Pwd SET SecureKey=? WHERE EMail=?"
	tx, err := db.Begin()
	if err != nil {
		return err.Error()
	}
	defer tx.Rollback()
	ua, err := tx.Exec(updateActive, 1, email)
	if err != nil {
		return err.Error()
	}
	uaCount, err := ua.RowsAffected()
	if err != nil {
		return err.Error()
	}
	uk, err := tx.Exec(updateKey, RndCodeCreator(15), email)
	if err != nil {
		return err.Error()
	}
	ukCount, err := uk.RowsAffected()
	if err != nil {

	}
	if err != nil {
		return err.Error()
	}
	tx.Commit()
	if uaCount > 0 && ukCount > 0 {
		return "SUCCESS"
	} else {
		return "FAIL"
	}
}
func UserInfoUpdate(email string, phoneNumber string, photoLink string, gender string, birthday string, userName string, nickName string) string {
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	sqlCMD, err := db.Prepare("UPDATE RealTimeCall_Userinfo SET PhoneNumber=?,ProfilePhoto=?,Gender=?,Birthday=?,UserName=?,DisplayName WHERE EMail=?")
	if err != nil {
		return err.Error()
	}
	defer sqlCMD.Close()
	res, err := sqlCMD.Exec(phoneNumber, photoLink, gender, birthday, userName, nickName, email)
	if err != nil {
		return err.Error()
	}
	affectCount, err := res.RowsAffected()
	if err != nil {
		return err.Error()
	}
	if affectCount > 0 {
		return "SUCCESS"
	} else {
		return "FAIL"
	}
}
func PasswordForget(email string) string {
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	rows, err := db.Query("SELECT EMail,SecureKey FROM RealTimeCall_Userinfo_Pwd WHERE EMail=?", email)
	if err != nil {
		return err.Error()
	}
	var url string
	mailAddress := "此E-mail尚未成為會員"
	var secureKey string
	for rows.Next() {
		if err := rows.Scan(&mailAddress, &secureKey); err != nil {
			return err.Error()
		}
		url = "點擊連結取得臨時密碼，請使用臨時密碼登入之後，更改密碼 \n\n https://www.manager-shop.xyz/v1/User/GetNewPassword?Umail=" + mailAddress + "&" + "Key=" + secureKey
	}
	if strings.Contains(mailAddress, "此E-mail尚未成為會員") {
		return mailAddress
	} else {
		MailSend(email, "[ShopManager]忘記密碼了嗎?", url)
	}
	return mailAddress
}

func SendRandomPwd(email string, secureKey string) string {
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	rows, err := db.Query("SELECT EMail FROM RealTimeCall_Userinfo_Pwd WHERE EMail=? AND SecureKey=?", email, secureKey)
	if err != nil {
		return err.Error()
	}
	var changeStatus string
	var tempPassword string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return err.Error()
		}
		tempPassword = RndCodeCreator(10)
		changeStatus = RndPasswordChange(email, tempPassword)
		log.Printf("TempPassword: %s,SHA: %s", tempPassword, shaProc(tempPassword))
	}
	if changeStatus == "SUCCESS" {
		MailSend(email, "[ShopManager]臨時密碼", "您的臨時密碼為：\n"+tempPassword+"\n\n 為方便日後使用，請儘速更改為自訂密碼。")
		return "SUCCESS"
	} else {
		return "FAIL"
	}
}
func PasswordChange(email string, originalPwd string, pwd string) string {
	//修改密碼
	shaPassword := shaProc(pwd)
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	sqlCMD, err := db.Prepare("UPDATE RealTimeCall_Userinfo_Pwd SET Password=?,SecureKey=? WHERE EMail=? AND Password=?")
	if err != nil {
		return err.Error()
	}
	defer sqlCMD.Close()
	res, err := sqlCMD.Exec(shaPassword, RndCodeCreator(15), email, shaProc(originalPwd))
	if err != nil {
		return err.Error()
	}
	affectCount, err := res.RowsAffected()
	if err != nil {
		return err.Error()
	}
	if affectCount > 0 {
		return "SUCCESS"
	} else {
		return "FAIL"
	}
}
func RndPasswordChange(email string, pwd string) string {
	//修改密碼
	shaPassword := shaProc(pwd)
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	sqlCMD, err := db.Prepare("UPDATE RealTimeCall_Userinfo_Pwd SET Password=?,SecureKey=? WHERE EMail=?")
	if err != nil {
		return err.Error()
	}
	defer sqlCMD.Close()
	res, err := sqlCMD.Exec(shaPassword, RndCodeCreator(15), email)
	if err != nil {
		return err.Error()
	}
	affectCount, err := res.RowsAffected()
	if err != nil {
		return err.Error()
	}
	if affectCount > 0 {
		return "SUCCESS"
	} else {
		return "FAIL"
	}
}
func DeleteUser(email string, pwd string) string {
	shaPassword := shaProc(pwd)
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	DelPwdQueryString := "DELETE RealTimeCall_Userinfo_Pwd WHERE EMail=? AND Password=?"
	DelMainQueryString := "DELETE RealTimeCall_Userinfo WHERE EMail=?"
	tx, err := db.Begin()
	if err != nil {
		return err.Error()
	}
	defer tx.Rollback()
	_, err = tx.Exec(DelPwdQueryString, email, shaPassword)
	if err != nil {
		return err.Error()
	}

	_, err = tx.Exec(DelMainQueryString, email)
	if err != nil {
		return err.Error()
	}
	if err = tx.Commit(); err != nil {
		return err.Error()
	} else {
		return "SUCCESS"
	}
}
func GameCardInsert(gamecardInfo ...string) (string, string) {
	var public string
	var private string

	db, err := sql.Open("mysql", connectionString_GameCard)
	if err != nil {
		public = "ERROR"
		private = "ERROR"
	}
	defer db.Close()
	publicKey := RndCodeCreator(10)
	privateKey := RndCodeCreator(15)
	userInsert := "INSERT INTO GameBCard.UserData(GameName,UserId,Server,LineId,Youtube,TwitchId,Instagram,FBId,GamplexId,DiscordId,Details,PhotoURL,PublicKey,PrivateKey,LastLoad)VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
	r, err := db.Exec(userInsert, gamecardInfo[0], gamecardInfo[1], gamecardInfo[2], gamecardInfo[3], gamecardInfo[4], gamecardInfo[5], gamecardInfo[6], gamecardInfo[7], gamecardInfo[8], gamecardInfo[9], gamecardInfo[10], gamecardInfo[11], gamecardInfo[12], publicKey, shaProc(privateKey), time.Now().UnixNano())
	if err != nil {
		public = "ERROR"
		private = "ERROR"
	}
	insertSuccess, err := r.RowsAffected()
	if err != nil {
		public = "ERROR"
		private = "ERROR"
	}
	if insertSuccess > 0 {
		public = publicKey
		private = privateKey
	} else {
		public = "ERROR"
		private = "ERROR"
	}
	return public, private
}
func DeleteCard(publicKey string, privateKey string) string {
	var resp string
	db, err := sql.Open("mysql", connectionString_GameCard)
	if err != nil {
		resp = "FAIL"
	}
	defer db.Close()
	deleteCount, err := db.Exec("DELETE GameBCard.UserData WHERE PublicKey=? AND PrivateKey=?", publicKey, privateKey)
	if err != nil {
		resp = "FAIL"
	}
	delAffect, err := deleteCount.RowsAffected()
	if err != nil {
		resp = "FAil"
	}
	if delAffect > 0 {
		resp = "SUCCESS"
	} else {
		resp = "FAIL"
	}
	return resp
}

func GetGameCardInfo(publicKey string) (map[string]string, error) {
	var (
		cardDetails map[string]string
		userId      string
		photoURL    string
		lineId      string
		fbId        string
		youtube     string
		twitchId    string
		ig          string
		gpx         string
		pubKey      string
		serverName  string
		details     string
		discordId   string
		gameName    string
	)

	db, err := sql.Open("mysql", connectionString_GameCard)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT UserId,PhotoURL,FBId,LineId,Youtube,TwitchId,Instagram,GamplexId,PublicKey,Server,Details,DiscordId,GameName FROM GameBCard.UserData WHERE PublicKey=?", publicKey)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		if err := rows.Scan(&userId, &photoURL, &fbId, &lineId, &youtube, &twitchId, &ig, &gpx, &pubKey, &serverName, &details, &discordId, &gameName); err != nil {
			return nil, err
		}
		cardDetails = map[string]string{
			"userid": userId, "photourl": photoURL, "fbid": fbId, "lineid": lineId, "youtube": youtube, "twitchid": twitchId,
			"ig": ig, "gamplex": gpx, "publickey": pubKey, "server": serverName, "details": details, "discordid": discordId, "gamename": gameName,
		}
	}
	return cardDetails, nil
}
func PreEditCard(publicKey string) string {
	var resp string
	db, err := sql.Open("mysql", connectionString_GameCard)
	if err != nil {
		resp = "FAIL"
	}
	defer db.Close()
	selRow, err := db.Query("SELECT PublicKey FROM GameBCard.UserData WHERE PublicKey=?", publicKey)
	if err != nil {
		resp = "FAIL"
	}
	for selRow.Next() {
		if err := selRow.Scan(&resp); err != nil {
			log.Fatal(err.Error())
		}
	}
	return resp
}

func EditCard(gameName string, userId string, serverName string, lineId string, youtube string, twitchId string, ig string, fb string, gamplex string, discordId string, details string, link string, publicKey string, privateKey string) string {
	var resp string
	db, err := sql.Open("mysql", connectionString_GameCard)
	if err != nil {
		resp = "EDIT_ERR"
	}
	defer db.Close()

	if link == "" {
		//無檔案上傳
		sqlCMD, err := db.Prepare("UPDATE GameBCard.UserData SET GameName=?,UserId=?,Server=?,LineId=?,Youtube=?,TwitchId=?,Instagram=?,FBId=?,GamplexId=?,DiscordId=?,Details=? WHERE PublicKey=? AND PrivateKey=?")
		if err != nil {
			resp = "EDIT_ERR"
		}
		defer sqlCMD.Close()
		res, err := sqlCMD.Exec(gameName, userId, serverName, lineId, youtube, twitchId, ig, fb, gamplex, discordId, details, publicKey, privateKey)
		if err != nil {
			resp = "EDIT_ERR"
		}
		affectRow, err := res.RowsAffected()
		if err != nil {
			resp = "EDIT_ERR"
		}
		if affectRow > 0 {
			resp = publicKey
		} else {
			resp = "NO_UPDATE"
		}
	} else {
		sqlCMD, err := db.Prepare("UPDATE GameBCard.UserData SET GameName=?,UserId=?,Server=?,LineId=?,Youtube=?,TwitchId=?,Instagram=?,FBId=?,GamplexId=?,DiscordId=?,Details=?,PhotoURL=? WHERE PublicKey=? AND PrivateKey=?")
		if err != nil {
			resp = "EDIT_ERR"
		}
		defer sqlCMD.Close()
		res, err := sqlCMD.Exec(gameName, userId, serverName, lineId, youtube, twitchId, ig, fb, gamplex, discordId, details, link, publicKey, privateKey)
		if err != nil {
			resp = "EDIT_ERR"
		}
		affectRow, err := res.RowsAffected()
		if err != nil {
			resp = "EDIT_ERR"
		}
		if affectRow > 0 {
			resp = publicKey
		} else {
			resp = "NO_UPDATE"
		}
	}
	return resp
}
func GameCardEmail(email string, publicKey string, privateKey string) string {
	var resp string
	var sendPublicKey string
	var sendPrivateKey string
	db, err := sql.Open("mysql", connectionString_GameCard)
	if err != nil {
		resp = "FAIL"
	}
	defer db.Close()
	selRow, err := db.Query("SELECT PublicKey,PrivateKey FROM GameBCard.UserData WHERE PublicKey=? AND PrivateKey=?", publicKey, privateKey)
	if err != nil {
		resp = "FAIL"
	}
	for selRow.Next() {
		if selRow.Scan(&sendPublicKey, &sendPrivateKey); err != nil {
			resp = "FAIL"
		}
	}
	if sendPublicKey != "" && sendPrivateKey != "" {
		MailSend(email, "[GameCard]遊戲名片", "名片連結： \n https://www.manager-shop.xyz/gc/web/View?public_key="+sendPublicKey+"\n 公鑰："+sendPublicKey+"\n 私鑰："+sendPrivateKey+"\n 請妥善保管。")
		resp = "SUCCESS"
	} else {
		resp = "FAIL"
	}
	return resp
}
func SSLVerification() string {
	db, err := sql.Open("mysql", connectionString_RealTime)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer db.Close()
	row, err := db.Query("SELECT VerifyCode FROM Verification")
	if err != nil {
		log.Fatal(err.Error())
	}
	var vcode string
	for row.Next() {
		if err := row.Scan(&vcode); err != nil {
			log.Fatal(err.Error())
		}
	}
	return vcode
}
func MailSend(targerMail string, subject string, body string) {
	from := "*@gmail.com"
	pass := "*"
	to := targerMail
	signature := "Doug Pr."
	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject:" + subject + "\n\n" +
		body + "\n\n" + signature

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}

	log.Print("sent, success")
}

func RndCodeCreator(codeCount int) string {
	//亂數碼產生
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "1234567890")
	b := make([]rune, codeCount)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
