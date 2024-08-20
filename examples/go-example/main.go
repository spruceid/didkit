package main

import (
	hm "crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/skip2/go-qrcode"
	"github.com/spruceid/didkit-go"
)

var credentials = gin.H{}
var requests = gin.H{}

func goDotEnvVariable(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	return os.Getenv(key)
}

func generateHMAC(query string, c *gin.Context) string {
	var key = []byte(goDotEnvVariable("HMAC_SECRET"))
	var mac = hm.New(sha256.New, key)
	mac.Write([]byte(query))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateCredential(id string, issuer string, issuance string, expiration string, expires string) gin.H {
	credentials[id] = gin.H{
		"type": "CredentialOffer",
		"credentialPreview": gin.H{
			"@context":          []string{"https://www.w3.org/2018/credentials/v1", "https://schema.org/"},
			"id":                id,
			"type":              "VerifiableCredential",
			"issuer":            issuer,
			"issuanceDate":      issuance,
			"expirationDate":    expiration,
			"credentialSubject": gin.H{},
		},
		"expires": expires,
	}
	return credentials[id].(gin.H)
}

func issueCredential(credential gin.H) gin.H {
	var vm = strings.Split(credential["issuer"].(string), ":")
	var options = gin.H{
		"proofPurpose":       "assertionMethod",
		"verificationMethod": fmt.Sprintf("%s#%s", credential["issuer"].(string), vm[len(vm)-1]),
	}
	var credentialStr, _ = json.Marshal(credential)
	var opt, _ = json.Marshal(options)
	var vc, _ = didkit.IssueCredential(string(credentialStr), string(opt), goDotEnvVariable("KEY"))
	var jsonVc gin.H
	json.Unmarshal([]byte(vc), &jsonVc)
	return jsonVc
}

func generateVP(host string) gin.H {
	var challenge = uuid.NewString()
	var credentialQuery = gin.H{
		"reason": "Sign in",
		"example": gin.H{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
			},
			"type": "VerifiableCredential",
		},
	}
	var query = gin.H{
		"type":            "QueryByExample",
		"credentialQuery": credentialQuery,
	}

	requests[challenge] = gin.H{
		"type":      "VerifiablePresentationRequest",
		"query":     query,
		"challenge": challenge,
		"domain":    host,
	}
	return requests[challenge].(gin.H)
}

func main() {
	router := gin.Default()
	router.Use(location.Default())
	godotenv.Load()

	router.LoadHTMLGlob("templates/*")
	//router.LoadHTMLFiles("templates/template1.html", "templates/template2.html")
	router.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{})
	})

	router.GET("/get-qr", func(c *gin.Context) {
		url := location.Get(c)
		var k, _ = didkit.GenerateEd25519Key()
		var id, _ = didkit.KeyToDID("key", k)
		var expires = time.Now().UTC().Add(time.Minute * 15).Format(time.RFC3339)
		var query = fmt.Sprintf("?id=%v&expires=%v", id, expires)
		query = fmt.Sprintf("%v&hmac=%v", query, generateHMAC(query, c))
		if pic, err := qrcode.Encode(fmt.Sprintf("%v%v/offer%v", url.Scheme, url.Host, query), qrcode.Medium, 256); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"Error generating QR Code": err.Error()})
			return
		} else {
			c.HTML(http.StatusOK, "get-qr.tmpl", gin.H{
				"qr":  base64.StdEncoding.EncodeToString(pic),
				"url": string(query),
			})
		}
	})

	router.GET("/present", func(c *gin.Context) {
		url := location.Get(c)
		if pic, err := qrcode.Encode(fmt.Sprintf("%v%v/vp-request", url.Scheme, url.Host), qrcode.Medium, 256); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"Error generating QR Code": err.Error()})
			return
		} else {
			c.HTML(http.StatusOK, "present.tmpl", gin.H{
				"qr":  base64.StdEncoding.EncodeToString(pic),
				"url": "/vp-request",
			})
		}
	})

	router.GET("/vp-request", func(c *gin.Context) {
		url := location.Get(c)
		c.JSON(http.StatusOK, generateVP(url.Host))
	})

	router.POST("/vp-request", func(c *gin.Context) {
		url := location.Get(c)

		var challenge = c.DefaultQuery("challenge", c.PostForm("challenge"))
		if challenge == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The field 'challenge' is required."})
			return
		}

		var presentation = c.DefaultQuery("presentation", c.PostForm("presentation"))
		if presentation == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The field 'presentation' is required."})
			return
		}

		var verifyOptions = gin.H{
			"challenge":    requests[challenge],
			"domain":       url.Host,
			"proofPurpose": "authentication",
		}

		var verifyStr, _ = json.Marshal(verifyOptions)

		var verifyResult, _ = didkit.VerifyPresentation(presentation, string(verifyStr))
		var resultObj gin.H
		json.Unmarshal([]byte(verifyResult), &resultObj)

		if len(resultObj["errors"].([]string)) != 0 {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": fmt.Sprintf("Can't verify presentation: %v", resultObj["errors"])})
			return
		}

		var vp gin.H
		json.Unmarshal([]byte(presentation), &vp)

		var vc = vp["verifiableCredential"].(gin.H)
		if vc == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to find credential."})
			return
		}

		var vcStr, _ = json.Marshal(vc)

		var credResult, _ = didkit.VerifyCredential(string(vcStr), string(verifyStr))
		json.Unmarshal([]byte(credResult), &resultObj)

		if len(resultObj["errors"].([]string)) != 0 {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": fmt.Sprintf("Can't verify credential: %v", resultObj["errors"])})
			return
		}

		if vp["holder"] != vc["credentialSubject"].(gin.H)["id"] {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Credential subject does not match holder"})
			return
		}
		c.JSON(http.StatusOK, gin.H{})
	})

	router.GET("/offer", func(c *gin.Context) {
		var id = c.Query("id")
		var hmac = c.Query("hmac")
		var expires = c.Query("expires")
		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The field 'id' is required."})
			return
		}

		if hmac == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The field 'hmac' is required."})
			return
		}

		if expires == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The field 'expires' is required."})
			return
		}

		var query = fmt.Sprintf("?id=%v&expires=%v", id, expires)
		var currentTime = time.Now().UTC()
		var exp, _ = time.Parse(time.RFC3339, expires)
		if currentTime.After(exp) {
			c.JSON(http.StatusGone, gin.H{"error": fmt.Sprintf("The offer expired at %v", expires)})
			return
		}
		if !hm.Equal([]byte(hmac), []byte(generateHMAC(query, c))) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid HMAC"})
			return
		}

		var issuer, _ = didkit.KeyToDID("key", goDotEnvVariable("KEY"))
		var issuance = currentTime.Format(time.RFC3339)
		var expiration = currentTime.Add(time.Minute * 15).Format(time.RFC3339)
		generateCredential(id, issuer, issuance, expiration, expires)
		c.JSON(http.StatusOK, credentials[id])
	})

	router.GET("/get-json", func(c *gin.Context) {
		var k, _ = didkit.GenerateEd25519Key()
		var id, _ = didkit.KeyToDID("key", k)
		var issuer, _ = didkit.KeyToDID("key", goDotEnvVariable("KEY"))
		var currentTime = time.Now().UTC()
		var issuance = currentTime.Format(time.RFC3339)
		var expiration = currentTime.Add(time.Minute * 15).Format(time.RFC3339)
		var expires = currentTime.Add(time.Minute * 15).Format(time.RFC3339)
		generateCredential(id, issuer, issuance, expiration, expires)
		var credential = credentials[id].(gin.H)["credentialPreview"]
		c.JSON(http.StatusOK, issueCredential(credential.(gin.H)))

	})

	router.POST("/offer", func(c *gin.Context) {
		var id = c.DefaultQuery("id", c.PostForm("id"))
		var subjectId = c.DefaultQuery("subject_id", c.PostForm("subject_id"))
		if subjectId == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The field 'subject_id' is required."})
			return
		}

		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The field 'id' is required."})
			return
		}
		var credential = credentials[id].(gin.H)["credentialPreview"]

		credential.(gin.H)["credentialSubject"] = gin.H{
			"id": subjectId,
		}
		c.JSON(http.StatusOK, issueCredential(credential.(gin.H)))
	})

	router.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
