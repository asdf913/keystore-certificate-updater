import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.function.FailableFunction;
import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import com.google.common.reflect.Reflection;

import io.github.toolfactory.narcissus.Narcissus;
import javassist.util.proxy.MethodHandler;
import javassist.util.proxy.ProxyFactory;
import javassist.util.proxy.ProxyObject;

class KeyStoreCertificateUpdaterTest {

	private static Method METHOD_ADD, METHOD_GET_NAME = null;

	@BeforeSuite
	void beforeSuite() throws NoSuchMethodException {
		//
		final Class<?> clz = KeyStoreCertificateUpdater.class;
		//
		(METHOD_ADD = clz.getDeclaredMethod("add", Collection.class, Object.class)).setAccessible(true);
		//
		(METHOD_GET_NAME = clz.getDeclaredMethod("getName", Member.class)).setAccessible(true);
		//
	}

	private static class IH implements InvocationHandler {

		private Boolean add, test, hasMoreElements = null;

		private Integer size = null;

		@Override
		public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
			//
			final String name = getName(method);
			//
			if (proxy instanceof Collection) {
				//
				if (Objects.equals(name, "add")) {
					//
					return add;
					//
				} else if (Objects.equals(name, "size")) {
					//
					return size;
					//
				} else if (Objects.equals(name, "stream")) {
					//
					return null;
					//
				} // if
					//
			} // if
				//
			if (proxy instanceof Member) {
				//
				if (Objects.equals(name, "getName")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof List) {
				//
				if (Objects.equals(name, "get")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Map) {
				//
				if (contains(Arrays.asList("get", "put"), name)) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Predicate) {
				//
				if (Objects.equals(name, "test")) {
					//
					return test;
					//
				} // if
					//
			} else if (proxy instanceof Entry) {
				//
				if (contains(Arrays.asList("getValue", "getKey"), name)) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof FailableFunction) {
				//
				if (Objects.equals(name, "apply")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Stream) {
				//
				if (Objects.equals(name, "collect")) {
					//
					return null;
					//
				} else if (Objects.equals(name, "filter")) {
					//
					return proxy;
					//
				} // if
					//
			} else if (proxy instanceof Enumeration) {
				//
				if (Objects.equals(name, "hasMoreElements")) {
					//
					return hasMoreElements;
					//
				} else if (Objects.equals(name, "nextElement")) {
					//
					return null;
					//
				} // if
					//
			} // if
				//
			throw new Throwable(name);
			//
		}

	}

	private static class MH implements MethodHandler {

		@Override
		public Object invoke(final Object self, final Method thisMethod, final Method proceed, final Object[] args)
				throws Throwable {
			//
			final String name = getName(thisMethod);
			//
			if (self instanceof Certificate && Objects.equals(name, "getEncoded")) {
				//
				return null;
				//
			} // if
				//
			throw new Throwable(name);
			//
		}

	}

	@Test
	void testNull() throws IllegalAccessException, InvocationTargetException {
		//
		final Method[] ms = KeyStoreCertificateUpdater.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType = null;
		//
		Object result = null;
		//
		String toString = null;
		//
		Object[] os = null;
		//
		Collection<Object> collection = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if (Objects.equals(parameterType = ArrayUtils.get(parameterTypes, j), Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.FALSE);
					//
				} else {
					//
					add(collection, null);
					//
				} // if
					//
			} // for
				//
			os = toArray(collection);
			//
			toString = Objects.toString(m);
			//
			result = Narcissus.invokeStaticMethod(m, os);
			//
			if (contains(Arrays.asList(Integer.TYPE, Boolean.TYPE), getReturnType(m))) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//
	}

	private static String getName(final Member instance) throws Throwable {
		try {
			final Object obj = invoke(METHOD_GET_NAME, null, instance);
			if (obj == null) {
				return null;
			} else if (obj instanceof String) {
				return (String) obj;
			}
			throw new Throwable(Objects.toString(obj.getClass()));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	void testNotNull() throws Throwable {
		//
		final Method[] ms = KeyStoreCertificateUpdater.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType, type = null;
		//
		Object result, object = null;
		//
		String toString, name = null;
		//
		Object[] os = null;
		//
		Collection<Object> collection = null;
		//
		IH ih = null;
		//
		Field[] fs = null;
		//
		Field f = null;
		//
		ProxyFactory proxyFactory = null;
		//
		MH mh = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getClass"),
							Arrays.equals(parameterTypes, new Object[] { Object.class }))) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if (Objects.equals(parameterType = ArrayUtils.get(parameterTypes, j), Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.FALSE);
					//
				} else if (parameterType != null && parameterType.isInterface()) {
					//
					if ((ih = ObjectUtils.getIfNull(ih, IH::new)) != null
							&& (fs = IH.class.getDeclaredFields()) != null) {
						//
						for (int k = 0; k < fs.length; k++) {
							//
							if ((f = ArrayUtils.get(fs, k)) == null) {
								//
								continue;
								//
							} // if
								//
							if (Objects.equals(type = f.getType(), Boolean.class)) {
								//
								Narcissus.setField(ih, f, Boolean.TRUE);
								//
							} else if (Objects.equals(type, Integer.class)) {
								//
								Narcissus.setField(ih, f, Integer.valueOf(0));
								//
							} // if
								//
						} // for
							//
					} // if
						//
					add(collection, Reflection.newProxy(parameterType, ih));
					//
				} else if (parameterType != null && parameterType.isArray()) {
					//
					add(collection, Array.newInstance(parameterType.getComponentType(), 0));
					//
				} else if (Objects.equals(parameterType, Class.class)) {
					//
					add(collection, Class.class);
					//
				} else if (Objects.equals(parameterType, X500Principal.class)) {
					//
					add(collection, new X500Principal(""));
					//
				} else if (Objects.equals(parameterType, KeyStore.class)) {
					//
					add(collection, KeyStore.getInstance(KeyStore.getDefaultType()));
					//
				} else if (Objects.equals(parameterType, InputStream.class)) {
					//
					add(collection, new ByteArrayInputStream("".getBytes()));
					//
				} else if (Objects.equals(parameterType, MessageDigest.class)) {
					//
					add(collection,
							Narcissus.allocateInstance(Class.forName("sun.security.provider.DSA$Raw$NullDigest20")));
					//
				} else if (Objects.equals(parameterType, HttpsURLConnection.class)) {
					//
					add(collection, Narcissus
							.allocateInstance(Class.forName("sun.net.www.protocol.https.HttpsURLConnectionImpl")));
					//
				} else if (Objects.equals(parameterType, Certificate.class)
						|| Objects.equals(parameterType, X509Certificate.class)) {
					//
					(proxyFactory = new ProxyFactory()).setSuperclass(parameterType);
					//
					object = null;
					//
					if (Objects.equals(parameterType, Certificate.class)) {
						//
						object = newInstance(getDeclaredConstructor(proxyFactory.createClass(), String.class),
								(Object) null);
						//
					} // if
						//
					if (object instanceof ProxyObject) {
						//
						((ProxyObject) object).setHandler(mh = ObjectUtils.getIfNull(mh, MH::new));
						//
					} // if
						//
					add(collection, object);
					//
				} else {
					//
					add(collection, Narcissus.allocateInstance(parameterType));
					//
				} // if
					//
			} // for
				//
			os = toArray(collection);
			//
			toString = Objects.toString(m);
			//
			result = Narcissus.invokeStaticMethod(m, os);
			//
			if (contains(Arrays.asList(Integer.TYPE, Boolean.TYPE), getReturnType(m))
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getClass"),
							Arrays.equals(parameterTypes, new Object[] { Object.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "getName"),
							Arrays.equals(parameterTypes, new Object[] { X500Principal.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "filter"),
							Arrays.equals(parameterTypes, new Object[] { Stream.class, Predicate.class }))) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//
	}

	private static <T> T newInstance(final Constructor<T> instance, final Object... args)
			throws InstantiationException, IllegalAccessException, InvocationTargetException {
		return instance != null ? instance.newInstance(args) : null;
	}

	private static <T> Constructor<T> getDeclaredConstructor(final Class<T> instance, final Class<?>... parameterTypes)
			throws NoSuchMethodException {
		return instance != null ? instance.getDeclaredConstructor(parameterTypes) : null;
	}

	private static boolean contains(final Collection<?> items, final Object item) {
		return items != null && items.contains(item);
	}

	private static Class<?> getReturnType(final Method instance) {
		return instance != null ? instance.getReturnType() : null;
	}

	private static Object[] toArray(final Collection<?> instance) {
		return instance != null ? instance.toArray() : null;
	}

	private static <E> void add(final Collection<E> items, final E item)
			throws IllegalAccessException, InvocationTargetException {
		invoke(METHOD_ADD, null, items, item);
	}

	private static Object invoke(final Method method, final Object instance, final Object... args)
			throws IllegalAccessException, InvocationTargetException {
		return method != null && method.getDeclaringClass() != null ? method.invoke(instance, args) : null;
	}

	private static void clear(final Collection<?> instance) {
		if (instance != null) {
			instance.clear();
		}
	}

	@Test
	void testMain() throws Exception {
		//
		KeyStoreCertificateUpdater.main(new String[] { "=", "= ", " =", " = ", "== " });
		//
	}

}