#include "lamu.h"
#include "File/file_system.h"

#include "../Core/Libraries/cpp-httplib/http.h"

#include "../Luau/VM/lualib.h"

static void http_request_tolua(const httplib::Request& req, lua_State* L)
{
    // TODO: finish entire api for request;
    luaL_newmetatable(L, "lamulib-http-meta-request");
    int metatable = lua_gettop(L);

    lua_pushcfunction(L,
        [](lua_State* L) {
            if (lua_isuserdata(L, 1))
            {
                const httplib::Request* request = (*static_cast<const httplib::Request**>(lua_touserdata(L, 1)));

                // TODO: return headers as Table
            }
            else {
                printf(ERR_INVALID_METHOD_CALL);
            }
            return 0;
        }, "headers"
    );
    lua_setfield(L, metatable, "headers");

    lua_pushvalue(L, metatable);
    lua_setfield(L, metatable, "__index");

    *static_cast<const httplib::Request**>(lua_newuserdata(L, sizeof(const httplib::Request*))) = &req;

    lua_pushvalue(L, metatable);
    lua_setmetatable(L, -2);
}
static void http_responce_tolua(httplib::Response& res, lua_State* L)
{
    // TODO: finish entire api for responce
    luaL_newmetatable(L, "lamulib-http-meta-responce");
    int metatable = lua_gettop(L);

    lua_pushcfunction(L,
        [](lua_State* L) {
            if (lua_isuserdata(L, 1))
            {
                const char* content = luaL_checkstring(L, 2);
                const char* content_type = luaL_checkstring(L, 3);
                httplib::Response* responce = (*static_cast<httplib::Response**>(lua_touserdata(L, 1)));
                responce->set_content(std::string(content), std::string(content_type));
            }
            else {
                printf(ERR_INVALID_METHOD_CALL);
            }
            return 0;
        }, "send"
    );
    lua_setfield(L, metatable, "send");

    lua_pushvalue(L, metatable);
    lua_setfield(L, metatable, "__index");

    *static_cast<httplib::Response**>(lua_newuserdata(L, sizeof(httplib::Response*))) = &res;

    lua_pushvalue(L, metatable);
    lua_setmetatable(L, -2);
}

namespace Lamu {
    int open_http(lua_State* L)
    {
        luaL_findtable(L, LUA_REGISTRYINDEX, "_MODULES", 1);

        lua_newtable(L);
        lua_pushstring(L, "new");

        lua_pushcfunction(L,
            [](lua_State* L) {
                luaL_newmetatable(L, "lamulib-http-meta");
                int metatable = lua_gettop(L);

                lua_pushcfunction(L,
                    [](lua_State* L) {
                        if (lua_isuserdata(L, 1) && lua_isfunction(L, 3))
                        {
                            HTTP::Server* Server = (*static_cast<HTTP::Server**>(lua_touserdata(L, 1)));
                            const char* path = luaL_checkstring(L, 2);

                            int callback_reference = lua_ref(L, 3);
                            Server->Get(path, [L, callback_reference](const httplib::Request& req, httplib::Response& res) {
                                lua_State* reqL = lua_newthread(L);
                                lua_xmove(L, reqL, 1);
                                http_request_tolua(req, reqL);
                                http_responce_tolua(res, reqL);
                                lua_getref(reqL, callback_reference);
                                lua_pushvalue(reqL, -2);
                                lua_pushvalue(reqL, -1);
                                lua_pcall(reqL, 2, LUA_MULTRET, 0);
                                lua_resume(reqL, L, 0);
                            });
                        }
                        else {
                            printf(ERR_INVALID_METHOD_CALL);
                        }
                        return 0;
                    }, "get"
                );
                lua_setfield(L, metatable, "Get");

                lua_pushcfunction(L,
                    [](lua_State* L) {
                        if (lua_isuserdata(L, 1))
                        {
                            const char* address = luaL_checkstring(L, 2);
                            int port = luaL_checkinteger(L, 3);
                            HTTP::Server* Server = (*static_cast<HTTP::Server**>(lua_touserdata(L, 1)));
                            Server->listen(std::string(address), port);
                        }
                        else {
                            printf(ERR_INVALID_METHOD_CALL);
                        }
                        return 0;
                    }, "listen"
                );
                lua_setfield(L, metatable, "listen");

                lua_pushvalue(L, metatable);
                lua_setfield(L, metatable, "__index");

                *static_cast<HTTP::Server**>(lua_newuserdata(L, sizeof(HTTP::Server*))) = new HTTP::Server;

                lua_pushvalue(L, metatable);
                lua_setmetatable(L, -2);

                return 1;
            }, "new"
        );
        lua_rawset(L, -3);

        lua_setfield(L, -2, "http");

        lua_pop(L, 1);

        return 1;
    }
}