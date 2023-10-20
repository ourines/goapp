package common

import (
	models "github.com/it234/goapp/internal/pkg/models/common"
	"github.com/it234/goapp/internal/pkg/models/sys"
	"github.com/it234/goapp/pkg/convert"

	"github.com/casbin/casbin"
)

const (
	PrefixUserID = "u"
	PrefixRoleID = "r"
)

var Enforcer *casbin.Enforcer

// 角色-URL导入
func InitCsbinEnforcer() (err error) {
	var enforcer *casbin.Enforcer
	// casbin模型
	casbinModel := `[request_definition]
	r = sub, obj, act
	
	[policy_definition]
	p = sub, obj, act
	
	[role_definition]
	g = _, _
	
	[policy_effect]
	e = some(where (p.eft == allow))
	
	[matchers]
	m = g(r.sub, p.sub) == true \
			&& keyMatch2(r.obj, p.obj) == true \
			&& regexMatch(r.act, p.act) == true \
			|| r.sub == "root"`
	enforcer, err = casbin.NewEnforcerSafe(
		casbin.NewModel(casbinModel),
	)
	if err != nil {
		return
	}

	// 查找所有权限
	var roles []sys.Role
	err = models.Find(&sys.Role{}, &roles)
	if err != nil {
		return
	}
	if len(roles) == 0 {
		Enforcer = enforcer
		return
	}
	
	for _, role := range roles {
		setRolePermission(enforcer, role.ID)
	}

	Enforcer = enforcer
	return
}

// 删除角色
func CsbinDeleteRole(roleids []uint64) {
	if Enforcer == nil {
		return
	}
	for _, rid := range roleids {
		Enforcer.DeletePermissionsForUser(PrefixRoleID + convert.ToString(rid))
		Enforcer.DeleteRole(PrefixRoleID + convert.ToString(rid))
	}
}

// 设置角色权限
// 重新设置角色权限后需要调用setRolePermission重新生成
func CsbinSetRolePermission(roleid uint64) {
	if Enforcer == nil {
		return
	}
	// 删除
	Enforcer.DeletePermissionsForUser(PrefixRoleID + convert.ToString(roleid))
	setRolePermission(Enforcer, roleid)
}

// setRolePermission 设置角色权限
// 
// 初始化casbin策略，循环role与menu 将内容写入数据库
func setRolePermission(enforcer *casbin.Enforcer, roleid uint64) {
	var rolemenus []sys.RoleMenu

	// 查找角色的菜单
	err := models.Find(&sys.RoleMenu{RoleID: roleid}, &rolemenus)
	if err != nil {
		return
	}

	for _, rolemenu := range rolemenus {
		// menu存在上级
		menu := sys.Menu{}
		where := sys.Menu{}
		where.ID = rolemenu.MenuID
		_, err = models.First(&where, &menu)
		if err != nil {
			return
		}
		// 3 表示具体操作
		if menu.MenuType == 3 {
			// 将角色的id写入casbin策略
			// r<rid> , "/api/<**>", "<method>"
			enforcer.AddPermissionForUser(PrefixRoleID+convert.ToString(roleid), "/api"+menu.URL, "GET|POST")
		}
	}
}

// 检查用户是否有权限
// 检查uid是否有资源访问的权限
func CsbinCheckPermission(userID, url, methodtype string) (bool, error) {
	return Enforcer.EnforceSafe(PrefixUserID+userID, url, methodtype)
}

// CsbinAddRoleForUser 用户角色处理
// 
// 
func CsbinAddRoleForUser(userid uint64)(err error){
	if Enforcer == nil {
		return
	}
	uid:=PrefixUserID+convert.ToString(userid)
	// 删除所有有关于uid的权限
	Enforcer.DeleteRolesForUser(uid)
	var adminsroles []sys.AdminsRole
	// 根据当前uid查找对应的角色id
	err = models.Find(&sys.AdminsRole{AdminsID: userid}, &adminsroles)
	if err != nil {
		return
	}
	// 遍历角色并写入casbin
	for _, adminsrole := range adminsroles {
		// ==> g, uid, rid
		Enforcer.AddRoleForUser(uid, PrefixRoleID+convert.ToString(adminsrole.RoleID))
	}
	return
}
