from django.db import models
from django.contrib.auth.models import User, AbstractUser
# Create your models here.
class User(AbstractUser):
    # 定义手机号
    mobile=models.CharField(max_length=11, unique=True, blank=False)
    #头像 简介
    avatar = models.ImageField(upload_to='avatar/%Y%m%d/', blank=True)
    user_desc = models.CharField(max_length=500, blank=True)
    #修改字段为手机号
    USERNAME_FIELD = 'mobile'


    # 创建超级管理员字段
    REQUIRED_FIELDS = ['username', 'email']

    class Meta:
        db_table = 'tb_user'  #修改表名
        verbose_name = '用户管理'  #admin后台显示
        verbose_name_plural = verbose_name #admin后台显示

    def __str__(self):
        return self.mobile