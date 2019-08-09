package test;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.JSONSerializer;
import com.alibaba.fastjson.serializer.ObjectSerializer;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * @author ：YangChen
 * @date ：Created in 2019-08-05 10:41
 * @description：
 * @modified By：
 * @version:
 */
public class stringToJsonSerializer implements ObjectSerializer {
    @Override
    public void write(JSONSerializer jsonSerializer, Object o, Object o1, Type type, int i) throws IOException {
        jsonSerializer.write(JSONObject.parseObject(o.toString()));
    }
}
