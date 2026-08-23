"""命令行管理工具

用法：
    python manage.py createsuperuser
    python manage.py createsuperuser --username admin --email a@b.com
    python manage.py changepassword <username>
    python manage.py initdb
    python manage.py list-users
"""
import argparse
import getpass
import sys

from app import create_app, db
from app.models import User, RamRole


def cmd_initdb(args):
    db.create_all()
    print("数据库表已创建/已存在。")


def cmd_createsuperuser(args):
    username = args.username or input("用户名：").strip()
    if not username:
        print("用户名不能为空")
        sys.exit(1)
    if User.query.filter_by(username=username).first():
        print(f"用户名 {username} 已存在")
        sys.exit(1)

    email = args.email or (input("邮箱（可留空）：").strip() or None)

    if args.password:
        password = args.password
    else:
        while True:
            password = getpass.getpass("密码：")
            if not password:
                print("密码不能为空")
                continue
            confirm = getpass.getpass("确认密码：")
            if password != confirm:
                print("两次密码不一致，请重新输入")
                continue
            break

    u = User(username=username, email=email, is_admin=True, is_active=True,
             display_name=args.display_name or f"管理员 {username}")
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    print(f"管理员账号 {username} 创建成功，可登录 http://localhost:5000/admin/")


def cmd_changepassword(args):
    user = User.query.filter_by(username=args.username).first()
    if user is None:
        print(f"用户 {args.username} 不存在")
        sys.exit(1)
    password = getpass.getpass("新密码：")
    if not password:
        print("密码不能为空")
        sys.exit(1)
    user.set_password(password)
    db.session.commit()
    print(f"{args.username} 的密码已更新")


def cmd_list_users(args):
    users = User.query.order_by(User.created_at.desc()).all()
    if not users:
        print("（暂无用户）")
        return
    print(f"{'ID':<4} {'用户名':<20} {'管理员':<6} {'启用':<4} {'角色数':<6} {'邮箱':<25}")
    for u in users:
        print(f"{u.id:<4} {u.username:<20} {'是' if u.is_admin else '否':<6} "
              f"{'是' if u.is_active else '否':<4} {len(u.roles):<6} {u.email or '':<25}")


def cmd_list_roles(args):
    roles = RamRole.query.order_by(RamRole.created_at.desc()).all()
    if not roles:
        print("（暂无 RAM Role）")
        return
    print(f"{'ID':<4} {'角色名':<25} {'启用':<4} {'ARN':<60} {'描述'}")
    for r in roles:
        print(f"{r.id:<4} {r.name:<25} {'是' if r.is_active else '否':<4} {r.arn:<60} {r.description or ''}")


def build_parser():
    p = argparse.ArgumentParser(description="iDaas 命令行管理工具")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("initdb", help="初始化数据库表")
    sp.set_defaults(func=cmd_initdb)

    sp = sub.add_parser("createsuperuser", help="创建管理员账号")
    sp.add_argument("--username", help="用户名")
    sp.add_argument("--email", help="邮箱")
    sp.add_argument("--display-name", dest="display_name", help="显示名")
    sp.add_argument("--password", help="密码（非交互模式；不传则交互输入）")
    sp.set_defaults(func=cmd_createsuperuser)

    sp = sub.add_parser("changepassword", help="修改密码")
    sp.add_argument("username", help="用户名")
    sp.set_defaults(func=cmd_changepassword)

    sp = sub.add_parser("list-users", help="列出所有用户")
    sp.set_defaults(func=cmd_list_users)

    sp = sub.add_parser("list-roles", help="列出所有 RAM Role")
    sp.set_defaults(func=cmd_list_roles)

    return p


def main():
    args = build_parser().parse_args()
    app = create_app()
    with app.app_context():
        args.func(args)


if __name__ == "__main__":
    main()
