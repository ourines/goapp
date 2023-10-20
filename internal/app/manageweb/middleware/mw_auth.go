package middleware

import (
	"strconv"
	"time"

	"github.com/it234/goapp/pkg/jwt"
	"github.com/it234/goapp/internal/app/manageweb/controllers/common"
	"github.com/it234/goapp/pkg/cache"
	"github.com/it234/goapp/pkg/convert"

	"github.com/gin-gonic/gin"
)

// UserAuthMiddleware 用户授权中间件
func UserAuthMiddleware(skipper ...SkipperFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(skipper) > 0 && skipper[0](c) {
			c.Next()
			return
		}
		var uuid string
		// 检查请求头中得到token 
		if t := c.GetHeader(common.TOKEN_KEY); t != "" {
			userInfo,ok:=jwt.ParseToken(t)
			if !ok {
					common.ResFailCode(c,"token 无效",50008)
			    return
			}
			// 检查token是否过期
			exptimestamp, _ := strconv.ParseInt(userInfo["exp"], 10, 64)
      		exp := time.Unix(exptimestamp, 0)
			ok = exp.After(time.Now())
			// 过期处理
			if !ok {
				common.ResFailCode(c,"token 过期",50014)
				return
			}
			uuid = userInfo["uuid"]
		}

		if uuid != "" {
			// 从缓存中查找
			val, err := cache.Get([]byte(uuid))

			if err != nil {
				// 缓存中没有
				common.ResFailCode(c,"token 无效",50008)
				return
			}
			// 转成string
			userID := convert.ToUint(string(val))
			// 设置context
			c.Set(common.USER_UUID_Key, uuid) 
			c.Set(common.USER_ID_Key, userID) 
		}
		if uuid == "" {
			common.ResFailCode(c,"用户未登录",50008)
			return
		}
	}
}
