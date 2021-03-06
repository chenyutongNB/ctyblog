from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from home.models import ArticleCategory, Article
from django.http.response import HttpResponseNotFound, HttpResponse


# Create your views here.
class IndexView(View):
    def get(self, request):

        # 获取所有分类信息
        categories = ArticleCategory.objects.all()
        # 接收用户点击的分类id
        cat_id = request.GET.get('cat_id', 1)
        # 根据分类id进行查询
        try:
            category = ArticleCategory.objects.get(id=cat_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseNotFound('没有这个分类')
        # 获取分页参数
        page_num = request.GET.get('page_num', 1)
        page_size = request.GET.get('page_size', 10)
        # 根据分类信息查询文章数据
        articles = Article.objects.filter(category=category)
        # 创建分页
        from django.core.paginator import Paginator, EmptyPage
        paginator = Paginator(articles, per_page=page_size)
        # 进行分页
        try:
            page_articles = paginator.page(page_num)
        except EmptyPage:
            return HttpResponseNotFound('empty page')
        # 总页数
        total_page = paginator.num_pages

        # 8.组织数据传递给模板
        context = {
            'categories':categories,
            'category':category,
            'articles':page_articles,
            'page_size':page_size,
            'total_page':total_page,
            'page_num':page_num,
        }
        # return HttpResponse('11111111')
        return render(request, 'index.html', context=context)

from home.models import Comment
class DetailView(View):

    def get(self, request):

        # 接收文章id信息
        id = request.GET.get('id')
        # 根据文章id进行文章数据的查询
        try:
            article=Article.objects.get(id=id)
        except Article.DoesNotExist:
            return render(request, '404.html')
        else:
            # 让浏览量+1
            article.total_views += 1
            article.save()

        # 查询分类数据
        categories = ArticleCategory.objects.all()

        # 查询浏览量前十的文数据
        hot_articles = Article.objects.order_by('-total_views')[:9]

        # 获取分页请求参数
        page_size = request.GET.get('page_size', 10)
        page_num = request.GET.get('page_num', 1)
        # 根据文章信息查询评论数据
        comments = Comment.objects.filter(article=article).order_by('-created')
        # 获取评论总数
        total_count = comments.count()
        # 创建分页器
        from django.core.paginator import Paginator,EmptyPage
        paginator = Paginator(comments,page_size)
        # 进行分页处理
        try:
            page_comments=paginator.page(page_num)
        except EmptyPage:
            return HttpResponseNotFound('empty page')
        # 总页数
        total_page=paginator.num_pages

        context={
            'categories':categories,
            'category':article.category,
            'article':article,
            'hot_articles':hot_articles,
            'total_count':total_count,
            'comments':page_comments,
            'page_size':page_size,
            'total_page':total_page,
            'page_num':page_num
        }
        return render(request,'detail.html',context=context)

    def post(self,request):

        # 接收信息
        user = request.user
        # 判断是否登录
        if user and user.is_authenticated:
            # 登录用户则可以接收 form数据
            # 接收评论数据
            id = request.POST.get('id')
            content = request.POST.get('content')
            # 验证文章是否存在
            try:
                article = Article.objects.get(id=id)
            except Article.DoesNotExist:
                return HttpResponseNotFound('没有此文章')
            #  保存评论数据
            Comment.objects.create(
                content=content,
                article=article,
                user=user
            )
            # 修改评论数量
            article.comments_count += 1
            article.save()

            # 刷新页面（重定向）
            path = reverse('home:detail')+'?id={}'.format(article.id)
            return redirect(path)
        else:
            # 未登录用户跳转到登录页面
            return redirect(reverse('users:login'))