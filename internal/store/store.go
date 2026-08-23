// Package store 提供 bbolt 二进制 KV 存储层
//
// 存储设计（单文件 .db，B+tree）：
//
//	bucketMeta        : 自增计数器  next_user_id / next_role_id / next_binding_id
//	bucketUsers       : uint64(id) → JSON(User)
//	bucketUsersIdx    : username   → uint64(id)        唯一约束
//	bucketRoles       : uint64(id) → JSON(RamRole)
//	bucketRolesName   : name       → uint64(id)        唯一约束
//	bucketRolesArn    : arn        → uint64(id)        唯一约束
//	bucketBindings    : uint64(id) → JSON(UserRole)
//	bucketBindingsIdx : "{user}:{role}" → uint64(id)  唯一约束
//	bucketSessions    : session_id → JSON(Session)    服务端会话
package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"idaas/internal/models"
)

var (
	// ErrNotFound 未找到记录
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists 唯一约束冲突
	ErrAlreadyExists = errors.New("already exists")
)

var (
	bucketMeta        = []byte("meta")
	bucketUsers       = []byte("users")
	bucketUsersIdx    = []byte("users_idx")
	bucketRoles       = []byte("roles")
	bucketRolesName   = []byte("roles_idx_name")
	bucketRolesArn    = []byte("roles_idx_arn")
	bucketBindings    = []byte("bindings")
	bucketBindingsIdx = []byte("bindings_idx")
	bucketSessions    = []byte("sessions")
)

var (
	keyNextUser    = []byte("next_user_id")
	keyNextRole    = []byte("next_role_id")
	keyNextBinding = []byte("next_binding_id")
)

// Session 服务端会话记录
type Session struct {
	ID        string    `json:"id"`
	UserID    uint64    `json:"user_id"`
	CSRFToken string    `json:"csrf_token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store 封装 bbolt 数据库
type Store struct {
	db *bbolt.DB
}

// Open 打开或创建 bbolt 数据库文件并初始化 bucket
func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{
			bucketMeta, bucketUsers, bucketUsersIdx,
			bucketRoles, bucketRolesName, bucketRolesArn,
			bucketBindings, bucketBindingsIdx, bucketSessions,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// ------------------------------------------------------------
// 通用工具
// ------------------------------------------------------------

func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func btoi(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (s *Store) nextID(key []byte) (uint64, error) {
	var id uint64
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if v := b.Get(key); v != nil {
			id = btoi(v)
		}
		id++
		return b.Put(key, itob(id))
	})
	return id, err
}

// ------------------------------------------------------------
// 用户 CRUD
// ------------------------------------------------------------

// CreateUser 创建用户，username 唯一
func (s *Store) CreateUser(u *models.User) error {
	if u.Username == "" {
		return errors.New("username 不能为空")
	}
	id, err := s.nextID(keyNextUser)
	if err != nil {
		return err
	}
	u.ID = id
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now

	return s.db.Update(func(tx *bbolt.Tx) error {
		idx := tx.Bucket(bucketUsersIdx)
		if idx.Get([]byte(u.Username)) != nil {
			return ErrAlreadyExists
		}
		if err := idx.Put([]byte(u.Username), itob(u.ID)); err != nil {
			return err
		}
		data, err := json.Marshal(u)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUsers).Put(itob(u.ID), data)
	})
}

// GetUser 按 ID 查询
func (s *Store) GetUser(id uint64) (*models.User, error) {
	var u models.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketUsers).Get(itob(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &u)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByUsername 按用户名查询
func (s *Store) GetUserByUsername(username string) (*models.User, error) {
	var u models.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		idx := tx.Bucket(bucketUsersIdx)
		idb := idx.Get([]byte(username))
		if idb == nil {
			return ErrNotFound
		}
		v := tx.Bucket(bucketUsers).Get(idb)
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &u)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUser 更新用户（用户名不可改）。返回 ErrAlreadyExists 当尝试改用户名为已占用名
func (s *Store) UpdateUser(u *models.User) error {
	u.UpdatedAt = time.Now().UTC()
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		old := b.Get(itob(u.ID))
		if old == nil {
			return ErrNotFound
		}
		var prev models.User
		if err := json.Unmarshal(old, &prev); err != nil {
			return err
		}
		// 用户名变更时维护索引
		if prev.Username != u.Username {
			idx := tx.Bucket(bucketUsersIdx)
			if idx.Get([]byte(u.Username)) != nil {
				return ErrAlreadyExists
			}
			if err := idx.Delete([]byte(prev.Username)); err != nil {
				return err
			}
			if err := idx.Put([]byte(u.Username), itob(u.ID)); err != nil {
				return err
			}
		}
		// 保留创建时间
		if !prev.CreatedAt.IsZero() {
			u.CreatedAt = prev.CreatedAt
		}
		data, err := json.Marshal(u)
		if err != nil {
			return err
		}
		return b.Put(itob(u.ID), data)
	})
}

// DeleteUser 删除用户及其全部角色绑定
func (s *Store) DeleteUser(id uint64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		ub := tx.Bucket(bucketUsers)
		ubd := ub.Get(itob(id))
		if ubd == nil {
			return ErrNotFound
		}
		var u models.User
		if err := json.Unmarshal(ubd, &u); err != nil {
			return err
		}
		// 删除全部绑定
		if err := deleteBindingsByUser(tx, id); err != nil {
			return err
		}
		if err := tx.Bucket(bucketUsersIdx).Delete([]byte(u.Username)); err != nil {
			return err
		}
		return ub.Delete(itob(id))
	})
}

// ListUsers 列出全部用户（按创建时间倒序）
func (s *Store) ListUsers() ([]*models.User, error) {
	var users []*models.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketUsers).Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var u models.User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			users = append(users, &u)
		}
		return nil
	})
	return users, err
}

// CountUsers 返回用户总数
func (s *Store) CountUsers() (int, error) {
	return s.count(bucketUsers)
}

// CountAdmins 返回管理员数
func (s *Store) CountAdmins() (int, error) {
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketUsers).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var u models.User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			if u.IsAdmin {
				n++
			}
		}
		return nil
	})
	return n, err
}

// ------------------------------------------------------------
// RAM 角色 CRUD
// ------------------------------------------------------------

// CreateRole 创建角色，name 与 arn 唯一
func (s *Store) CreateRole(r *models.RamRole) error {
	if r.Name == "" || r.ARN == "" {
		return errors.New("name 与 arn 不能为空")
	}
	id, err := s.nextID(keyNextRole)
	if err != nil {
		return err
	}
	r.ID = id
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now

	return s.db.Update(func(tx *bbolt.Tx) error {
		nameB := tx.Bucket(bucketRolesName)
		arnB := tx.Bucket(bucketRolesArn)
		if nameB.Get([]byte(r.Name)) != nil || arnB.Get([]byte(r.ARN)) != nil {
			return ErrAlreadyExists
		}
		if err := nameB.Put([]byte(r.Name), itob(r.ID)); err != nil {
			return err
		}
		if err := arnB.Put([]byte(r.ARN), itob(r.ID)); err != nil {
			return err
		}
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRoles).Put(itob(r.ID), data)
	})
}

// GetRole 按 ID 查询
func (s *Store) GetRole(id uint64) (*models.RamRole, error) {
	var r models.RamRole
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketRoles).Get(itob(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &r)
	})
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateRole 更新角色（维护 name/arn 唯一索引）
func (s *Store) UpdateRole(r *models.RamRole) error {
	r.UpdatedAt = time.Now().UTC()
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRoles)
		old := b.Get(itob(r.ID))
		if old == nil {
			return ErrNotFound
		}
		var prev models.RamRole
		if err := json.Unmarshal(old, &prev); err != nil {
			return err
		}
		nameB := tx.Bucket(bucketRolesName)
		arnB := tx.Bucket(bucketRolesArn)
		if prev.Name != r.Name {
			if nameB.Get([]byte(r.Name)) != nil {
				return ErrAlreadyExists
			}
			nameB.Delete([]byte(prev.Name))
			nameB.Put([]byte(r.Name), itob(r.ID))
		}
		if prev.ARN != r.ARN {
			if arnB.Get([]byte(r.ARN)) != nil {
				return ErrAlreadyExists
			}
			arnB.Delete([]byte(prev.ARN))
			arnB.Put([]byte(r.ARN), itob(r.ID))
		}
		if !prev.CreatedAt.IsZero() {
			r.CreatedAt = prev.CreatedAt
		}
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return b.Put(itob(r.ID), data)
	})
}

// DeleteRole 删除角色及所有绑定
func (s *Store) DeleteRole(id uint64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRoles)
		rd := b.Get(itob(id))
		if rd == nil {
			return ErrNotFound
		}
		var r models.RamRole
		if err := json.Unmarshal(rd, &r); err != nil {
			return err
		}
		if err := deleteBindingsByRole(tx, id); err != nil {
			return err
		}
		tx.Bucket(bucketRolesName).Delete([]byte(r.Name))
		tx.Bucket(bucketRolesArn).Delete([]byte(r.ARN))
		return b.Delete(itob(id))
	})
}

// ListRoles 列出全部角色（创建时间倒序）
func (s *Store) ListRoles() ([]*models.RamRole, error) {
	var roles []*models.RamRole
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketRoles).Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var r models.RamRole
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			roles = append(roles, &r)
		}
		return nil
	})
	return roles, err
}

// CountRoles 角色总数
func (s *Store) CountRoles() (int, error) { return s.count(bucketRoles) }

// BindingCountByRole 返回绑定到该角色的用户数
func (s *Store) BindingCountByRole(roleID uint64) (int, error) {
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketBindings).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var b models.UserRole
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			if b.RoleID == roleID {
				n++
			}
		}
		return nil
	})
	return n, err
}

// ------------------------------------------------------------
// 用户-角色绑定 CRUD
// ------------------------------------------------------------

func bindingIndexKey(userID, roleID uint64) []byte {
	return []byte(fmt.Sprintf("%d:%d", userID, roleID))
}

// CreateBinding 创建绑定，(user_id, role_id) 唯一
func (s *Store) CreateBinding(b *models.UserRole) error {
	id, err := s.nextID(keyNextBinding)
	if err != nil {
		return err
	}
	b.ID = id
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		idx := tx.Bucket(bucketBindingsIdx)
		key := bindingIndexKey(b.UserID, b.RoleID)
		if idx.Get(key) != nil {
			return ErrAlreadyExists
		}
		if err := idx.Put(key, itob(b.ID)); err != nil {
			return err
		}
		data, err := json.Marshal(b)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketBindings).Put(itob(b.ID), data)
	})
}

// GetBinding 按 ID 查询绑定
func (s *Store) GetBinding(id uint64) (*models.UserRole, error) {
	var b models.UserRole
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketBindings).Get(itob(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &b)
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// DeleteBinding 删除绑定
func (s *Store) DeleteBinding(id uint64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bb := tx.Bucket(bucketBindings)
		v := bb.Get(itob(id))
		if v == nil {
			return ErrNotFound
		}
		var b models.UserRole
		if err := json.Unmarshal(v, &b); err != nil {
			return err
		}
		tx.Bucket(bucketBindingsIdx).Delete(bindingIndexKey(b.UserID, b.RoleID))
		return bb.Delete(itob(id))
	})
}

// ListBindingsByUser 列出用户全部绑定（携带 Role，仅返回角色仍启用的绑定用于门户）
func (s *Store) ListBindingsByUser(userID uint64, activeOnly bool) ([]*models.BindingView, error) {
	var out []*models.BindingView
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketBindings).Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var b models.UserRole
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			if b.UserID != userID {
				continue
			}
			rd := tx.Bucket(bucketRoles).Get(itob(b.RoleID))
			if rd == nil {
				continue
			}
			var r models.RamRole
			if err := json.Unmarshal(rd, &r); err != nil {
				return err
			}
			if activeOnly && !r.IsActive {
				continue
			}
			out = append(out, &models.BindingView{UserRole: b, Role: &r})
		}
		return nil
	})
	return out, err
}

// ListBindingsByUserRaw 不携带 Role，用于编辑页（含已停用角色）
func (s *Store) ListBindingsByUserRaw(userID uint64) ([]*models.BindingView, error) {
	return s.ListBindingsByUser(userID, false)
}

// CountBindings 绑定总数
func (s *Store) CountBindings() (int, error) { return s.count(bucketBindings) }

// deleteBindingsByUser 在事务内删除用户全部绑定
func deleteBindingsByUser(tx *bbolt.Tx, userID uint64) error {
	bb := tx.Bucket(bucketBindings)
	idx := tx.Bucket(bucketBindingsIdx)
	var toDel [][]byte
	c := bb.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var b models.UserRole
		if err := json.Unmarshal(v, &b); err != nil {
			return err
		}
		if b.UserID == userID {
			toDel = append(toDel, k)
			idx.Delete(bindingIndexKey(b.UserID, b.RoleID))
		}
	}
	for _, k := range toDel {
		if err := bb.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// deleteBindingsByRole 在事务内删除角色全部绑定
func deleteBindingsByRole(tx *bbolt.Tx, roleID uint64) error {
	bb := tx.Bucket(bucketBindings)
	idx := tx.Bucket(bucketBindingsIdx)
	var toDel [][]byte
	c := bb.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var b models.UserRole
		if err := json.Unmarshal(v, &b); err != nil {
			return err
		}
		if b.RoleID == roleID {
			toDel = append(toDel, k)
			idx.Delete(bindingIndexKey(b.UserID, b.RoleID))
		}
	}
	for _, k := range toDel {
		if err := bb.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// AvailableRoles 返回用户未绑定的角色（用于编辑页下拉）
func (s *Store) AvailableRoles(userID uint64) ([]*models.RamRole, error) {
	bound := map[uint64]bool{}
	bindings, err := s.ListBindingsByUserRaw(userID)
	if err != nil {
		return nil, err
	}
	for _, b := range bindings {
		bound[b.RoleID] = true
	}
	var out []*models.RamRole
	all, err := s.ListRoles()
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if !bound[r.ID] {
			out = append(out, r)
		}
	}
	return out, nil
}

// ------------------------------------------------------------
// 会话
// ------------------------------------------------------------

// CreateSession 持久化会话
func (s *Store) CreateSession(sess *Session) error {
	if sess.ID == "" {
		return errors.New("session id 不能为空")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		data, err := json.Marshal(sess)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketSessions).Put([]byte(sess.ID), data)
	})
}

// GetSession 按 ID 查询会话；过期则视为不存在
func (s *Store) GetSession(id string) (*Session, error) {
	var sess Session
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketSessions).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		if err := json.Unmarshal(v, &sess); err != nil {
			return err
		}
		if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// DeleteSession 删除会话
func (s *Store) DeleteSession(id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSessions).Delete([]byte(id))
	})
}

// ------------------------------------------------------------
// 辅助
// ------------------------------------------------------------

func (s *Store) count(bucket []byte) (int, error) {
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			n++
		}
		return nil
	})
	return n, err
}
