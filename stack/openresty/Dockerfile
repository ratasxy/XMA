FROM openresty/openresty:jammy

RUN apt update && \
    apt install -y openssl && \
    opm get openresty/lua-resty-redis && \
    opm get openresty/lua-resty-memcached && \
    opm get openresty/lua-resty-lrucache && \
    opm get fffonion/lua-resty-openssl

RUN wget http://luarocks.org/releases/luarocks-2.0.13.tar.gz && \
    tar -xzvf luarocks-2.0.13.tar.gz && \
    cd luarocks-2.0.13/  && \
    ./configure --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit/ \
        --lua-suffix=jit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 && \
    make && \
    make install

RUN luarocks install rxi-json-lua

COPY ./lua-resty-transparent-proxy /opt/openresty
WORKDIR /opt/openresty
RUN mkdir logs && \
    touch logs/error.log && \
    touch logs/access.log

CMD nginx -p `pwd` -c conf/nginx.conf &&  tail -f logs/*