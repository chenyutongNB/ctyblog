import re
from django.shortcuts import redirect
from django.urls import reverse
from django.db import DatabaseError
from django.http import HttpResponse, request
from django.shortcuts import render

import logging
from users.models import User
logger = logging.getLogger('django')
from random import randint
from libs.yuntongxun.sms import CCP
from django.views import View

# 注册视图
from utils.response_code import RETCODE


class RegisterView(View):

    def get(self, request):
        return render(request, 'register.html')

    def post(self,requset):
        #接收数据
        mobile=requset.POST.get('mobile')
        password=requset.POST.get('password')
        password2=requset.POST.get('password2')
        smscode=requset.POST.get('sms_code')
        #验证数据
         #参数知否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必要参数')
         #手机号格式是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合')
         #密码是否符合格式
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合,输入8-20位密码')
        # 密码和确认密码一致
        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')


         #短信雁阵吗是否和redis一致
        redis_conn=get_redis_connection('default')
        redis_sms_code=redis_conn.get('sms:%s'%mobile)
        if redis_sms_code is None:
            return  HttpResponseBadRequest('验证马过期')
        if smscode != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        #保存数据
        try:
          user=User.objects.create_user(username=mobile,mobile=mobile,password=password)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')
        #返回响应跳转到指定页面
        #暂时返回成功，后期再跳转
        #reverse 进行重定向namespase:
        return redirect(reverse('home:index'))
        # return HttpResponse('注册成功，重定向首页')


from libs.captcha.captcha import captcha
from django.http.response import HttpResponseBadRequest, JsonResponse
from django_redis import get_redis_connection


class ImageCodeView(View):
    def get(self, request):
        uuid = request.GET.get('uuid')
        # 判断uuid是否获取
        if uuid is None:
            return HttpResponseBadRequest('没有传递')
        # 通过调用captcha来生成图片验证码（图片二进制和图片内容）
        text, image = captcha.generate_captcha()
        # 将图片内容保存到redis中
        # uuid作为key
        # seconds过期秒
        # 图作为value
        redis_conn = get_redis_connection('default')
        redis_conn.setex('img:%s' % uuid, 300, text)

        # 返回图片二进制
        return HttpResponse(image, content_type='image/jpeg')


class SmsCodeView(View):

    def get(self, request):
        # 接收参数(查询字符串形式传递)
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')

        # 参数验证（参数是否齐全，图片验证码验证（链接redis，判断验证码是否过期，若未过期，获取后删除，比对验证码））
        if not all([mobile, image_code, uuid]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必要参数'})
        redis_conn = get_redis_connection('default')
        redis_image_code = redis_conn.get('img:%s' %uuid)
        if redis_image_code is None:
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码过期'})
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)
        if redis_image_code.decode().lower() != image_code.lower():
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证瓦特了'})

        # 生成短信验证码
        sms_code = '%06d' % randint(0, 999999)
        # 为了比对，可以将短信验证码记录到日志
        logger.info(sms_code)
        # 保存到redis中
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)
        # 发送
        CCP().send_template_sms(mobile, [sms_code, 5], 1)
        # 返回响应
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '发送成功'})
class LoginView(View):

    def get(self,request):
        #接受参数

        #参数验证
        #手机号
        #验证码
        #用户认证登录
        #状态保持
        #根据用户选择的是否记住登录状态来判断
        #为了首页显示我们需要设置的cookie信息
        #响应

        return render(request,'login.html')

    def post(self,request):
        # 接受参数
        mobile=request.POST.get('mobile')
        password=request.POST.get('password')
        remember=request.POST.get('remember')

        # 参数验证
        # 手机号
        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        # 验证码
        if not re.match(r'^[a-zA-Z0-9]{8,20}$',password):
            return HttpResponseBadRequest('密码不符合规则')
        # 用户认证登录
        # 采用自带的认证方式进行
        # 如果我们的用户名和密码正确，会返回user
        # 如果我们的用户名和密码不正确，会返回None
        from django.contrib.auth import authenticate
        # 默认的认证方法是针对于username字段进行用户名判断
        # 手机号，修改字段
        #  我们需要到User模型中进行修改，等测试出现问题的时候，我们再修改
        user = authenticate(mobile=mobile, password=password)
        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')
        # 状态保持
        from django.contrib.auth import login
        login(request, user)
        # 根据用户选择的是否记住登录状态来判断
        next_page=request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))

        if remember != 'on':#没有记住用户信息
            # 浏览器关闭之后
            request.session.set_expiry(0)
            response.set_cookie('is_login',True)
            response.set_cookie('username',user.username,max_age=14*24*3600)

        else:
            # 默认2周
            request.session.set_expiry(None)
            response.set_cookie('is_login',True,max_age=14*24*3600)
            response.set_cookie('username',user.username,max_age=14*24*3600)


        # 为了首页显示我们需要设置的cookie信息
        # 响应
        return response
from django.contrib.auth import logout
class LogoutView(View):

    def get(self, request):
        # session数据清除
        logout(request)
        # cookie删除
        response = redirect(reverse('home:index'))
        response.delete_cookie('is_login')
        #  跳转首页
        return response

class ForgetPasswordView(View):

    def get(self, request):
        return render(request, 'forget_password.html')

    def post(self,request):
        #接收数据
        mobile=request.POST.get('mobile')
        password=request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode=request.POST.get('sms_code')
        #验证数据
            #判断参数
        if not all([mobile,password,password2,smscode]):
            return HttpResponseBadRequest('参数不全')
            #判断手机号
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合')
            #判断密码
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合,输入8-20位密码')
            # 密码和确认密码一致
        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')
            #判断验证码
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('验证码过期')
        if smscode != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        #查询
            #如果查询出手机信息，则进行修改密码
        try:
            user=User.objects.get(mobile=mobile)
        except User.DoesNotExist:
          try:
           user=User.objects.create_user(username=mobile, mobile=mobile, password=password)
          except Exception:
            return HttpResponseBadRequest('修改失败')
          # 若无，创建新用户
        else:
            user.set_password(password)
            user.save()

        # 页面跳转登录
        response=redirect(reverse('users:login'))
        # 返回响应
        return response
from django.contrib.auth.mixins import LoginRequiredMixin
# 如果用户未登录的话，则会进行默认的跳转
# 默认的跳转连接是：accounts/login/?next=xxx
class UserCenterView(LoginRequiredMixin, View):

    def get(self, request):
        # 获得登录用户的信息
        user = request.user
        # 组织获取用户的信息
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc
        }
        return render(request, 'center.html', context=context)

    def post(self, request):

        user = request.user
        # 接收参数
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)
        avatar = request.FILES.get('avatar')
        # 将参数保存
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('修改失败，请稍后再试')
        # 更新cookie中的username
        # 刷新当前页面
        response = redirect(reverse('users:center'))
        response.set_cookie('username', user.username, max_age=14*3600*24)

        # 响应
        return response

from home.models import ArticleCategory, Article
class WriteBlogView(LoginRequiredMixin, View):

    def get(self,request):
        #查询分类模型
        categories = ArticleCategory.objects.all()

        context = {
            'categories': categories
        }
        return render(request, 'write_blog.html', context=context)

    def post(self, request):


        # 接收数据
        avatar = request.FILES.get('avatar')
        title = request.POST.get('title')
        category_id = request.POST.get('category')
        tags = request.POST.get('tags')
        sumary = request.POST.get('sumary')
        content = request.POST.get('content')
        user = request.user

        # 验证数据
        # 验证参数是否齐全
        if not all([avatar, title, category_id, sumary, content]):
            return HttpResponseBadRequest('参数不全呀')
        # 判断分类id
        try:
            category = ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有此分类呢')
        # 数据入库
        try:
            article = Article.objects.create(
                author=user,
                avatar=avatar,
                title=title,
                category=category,
                tags=tags,
                sumary=sumary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败了哈哈哈，请稍后再试')
        # 跳转到指页面
        return redirect(reverse('home:index'))

