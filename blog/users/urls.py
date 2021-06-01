# 进行users子应用的视图路由
from django.urls import path
from users.views import RegisterView, ImageCodeView, SmsCodeView, LoginView, LogoutView, ForgetPasswordView, \
    UserCenterView, WriteBlogView

urlpatterns =[
    path('register/', RegisterView.as_view(), name='register'), # 第一个参数就是路由,第二个参数，视图函数名

    # 图片验证路由
    path('imagecode/', ImageCodeView.as_view(), name='imagecode'),
    # 短信发送
    path('smscode/', SmsCodeView.as_view(), name='smscode'),
    # 登录路由
    path('login/', LoginView.as_view(), name='login'),
    # 退出登录路由
    path('logout/', LogoutView.as_view(), name='logout'),
    # 忘记密码
    path('forgetpassword/', ForgetPasswordView.as_view(), name='forgetpassword'),
    # 个人中心
    path('center/', UserCenterView.as_view(), name='center'),
    # 写博客的路由
    path('writeblog/',WriteBlogView.as_view(),name='writeblog'),
]
