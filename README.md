# heanbian-jwt

## 前提条件

JDK11+

## pom.xml

具体版本，可以上Maven中央仓库查询

```
<dependency>
	<groupId>com.heanbian.block</groupId>
	<artifactId>heanbian-jwt</artifactId>
	<version>1.0.2</version>
</dependency>
```

## 使用示例

```
import com.heanbian.block.jwt.*;

public class Test {

	public static void main(String[] args) {
		JwtTemplate template = new JwtTemplate();
		
		...
	}
}
```

说明：支持RSA的JWT生成token解析工具类。