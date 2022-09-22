# 基于ip2region的IP过滤模块

## 编译
进入nginx源码目录
``` shell
./configure --prefix=/home/ubuntu/deploy/nginx --add-module=/home/ubuntu/ngx_ip2region_access_module --with-cc-opt="-I /home/ubuntu/ngx_ip2region_access_module"
```
## 配置
```
server {
    listen       80;
    server_name  localhost;
    allow_region 河北;
    allow_region 北京;
    
    location / {
        root   html;
        index  index.html index.htm;
    }
}
```