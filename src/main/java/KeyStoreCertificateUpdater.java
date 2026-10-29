import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.validator.routines.DomainValidator;
import org.d2ab.function.ObjIntPredicate;

import io.github.toolfactory.narcissus.Narcissus;

public class KeyStoreCertificateUpdater {

	public static void main(final String[] args) throws Exception {
		//
		final Map<String, String> map = toMap(args);
		//
		final String url = get(map, "url");
		//
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		//
		System.out.println("URL                 =" + url);
		//
		final Certificate certificate = getCertfiicate(url);
		//
		System.out.printf("Certificate(%1$s)=%2$s%3$s", getAlgorithm(md),
				testAndApply(Objects::nonNull,
						testAndApply(Objects::nonNull, getEncoded(certificate), x -> digest(md, x), null),
						Hex::encodeHexString, null),
				System.lineSeparator());
		//
		final File keyStoreFile = testAndApply(Objects::nonNull, get(map, "keyStore"), File::new, null);
		//
		System.out.println("keyStore            =" + getAbsolutePath(keyStoreFile));
		//
		final char[] password = toCharArray(get(map, "password"));
		//
		boolean found = false;
		//
		try (final InputStream is = testAndApply(Objects::nonNull,
				testAndApply(Objects::nonNull, keyStoreFile, FileUtils::readFileToByteArray, null),
				ByteArrayInputStream::new, null)) {
			//
			final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			//
			boolean load = false;
			//
			if (is != null) {
				//
				load(keyStore, is, password);
				//
				load = true;
				//
			} // if
				//
			String alias = null;
			//
			Certificate c = null;
			//
			final Enumeration<String> aliases = load ? aliases(keyStore) : null;
			//
			while (hasMoreElements(aliases)) {
				//
				if (isCertificateEntry(keyStore, alias = nextElement(aliases))
						&& (c = getCertificate(keyStore, alias)) != null
						&& Arrays.equals(getEncoded(certificate), getEncoded(c)) && (found = true)) {
					//
					break;
					//
				} // if
					//
			} // while
				//
			if (!found && certificate != null && load) {
				//
				final X509Certificate x509Certificate = cast(X509Certificate.class, certificate);
				//
				final DateFormat df = new SimpleDateFormat("yyyyMMdd");
				//
				System.out.println("alias               =" + (alias = StringUtils.joinWith("_",
						StringUtils.substringAfter(getName(getSubjectX500Principal(x509Certificate)), '='),
						df.format(getNotBefore(x509Certificate)), df.format(getNotAfter(x509Certificate)))));
				//
				keyStore.setCertificateEntry(alias, certificate);
				//
				try (final OutputStream os = new FileOutputStream(keyStoreFile)) {
					//
					keyStore.store(os, password);
					//
				} // try
					//
				System.out.println("Certificate is added in keystore " + keyStoreFile);
				//
			} else if (keyStoreFile != null) {
				//
				System.out.println("Certificate is found in keystore " + keyStoreFile);
				//
			} // if
				//
		} // try
			//
	}

	private static char[] toCharArray(final String instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(y -> size(y) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "value")), Collectors.toList()),
				y -> get(y, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.toCharArray() : null;
		//
	}

	private static Date getNotBefore(final X509Certificate instnace) {
		return instnace != null ? instnace.getNotBefore() : null;
	}

	private static Date getNotAfter(final X509Certificate instnace) {
		return instnace != null ? instnace.getNotAfter() : null;
	}

	private static String getAbsolutePath(final File instance) {
		return instance != null && instance.getPath() != null ? instance.getAbsolutePath() : null;
	}

	private static String getAlgorithm(final MessageDigest instance) {
		return instance != null ? instance.getAlgorithm() : null;
	}

	private static byte[] getEncoded(final Certificate instance) throws CertificateEncodingException {
		return instance != null ? instance.getEncoded() : null;
	}

	private static Certificate getCertfiicate(final String url) throws IOException {
		//
		final HttpsURLConnection httpsURLConnection = cast(HttpsURLConnection.class, openConnection(testAndApply(x -> {
			//
			if (x == null) {
				//
				return false;
				//
			} // if
				//
			final Field field = testAndApply(y -> size(y) == 1,
					collect(filter(
							stream(testAndApply(Objects::nonNull, getClass(x), FieldUtils::getAllFieldsList, null)),
							f -> Objects.equals(getName(f), "value")), Collectors.toList()),
					y -> get(y, 0), null);
			//
			return field == null || Narcissus.getField(x, field) != null;
			//
		}, url, URL::new, null)));
		//
		connect(httpsURLConnection);
		//
		final List<Certificate> list = collect(
				filter(testAndApply(Objects::nonNull, getServerCertificates(httpsURLConnection), Arrays::stream, null),
						x -> isValid(DomainValidator.getInstance(),
								longestCommonSubstring(url,
										getName(getSubjectX500Principal(cast(X509Certificate.class, x)))))),
				Collectors.toList());
		//
		List<Certificate> result = null;
		//
		for (int i = 0; i < size(list); i++) {
			//
			add(result = ObjectUtils.getIfNull(result, ArrayList::new), get(list, i));
			//
		} // for
			//
		disconnect(httpsURLConnection);
		//
		if (size(result) > 1) {
			//
			throw new IllegalStateException();
			//
		} // if
			//
		return testAndApply(x -> size(x) == 1, result, x -> get(x, 0), null);
		//
	}

	private static byte[] digest(final MessageDigest instance, final byte[] input) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "digestBuffer")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.digest(input) : null;
		//
	}

	private static <E> void add(final Collection<E> instance, final E item) {
		if (instance != null) {
			instance.add(item);
		}
	}

	private static Certificate getCertificate(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "initialized")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || (field != null && Objects.equals(field.getType(), Boolean.TYPE)
				&& Narcissus.getBooleanField(instance, field)) ? instance.getCertificate(alias) : null;
		//
	}

	private static boolean isCertificateEntry(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null) {
			//
			return false;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "initialized")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return (field == null || (field != null && Objects.equals(field.getType(), Boolean.TYPE)
				&& Narcissus.getBooleanField(instance, field))) && instance.isCertificateEntry(alias);
		//
	}

	private static <E> E nextElement(final Enumeration<E> instance) {
		return instance != null ? instance.nextElement() : null;
	}

	private static boolean hasMoreElements(final Enumeration<?> instance) {
		return instance != null && instance.hasMoreElements();
	}

	private static Enumeration<String> aliases(final KeyStore instance) throws KeyStoreException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "initialized")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || (field != null && Objects.equals(field.getType(), Boolean.TYPE)
				&& Narcissus.getBooleanField(instance, field)) ? instance.aliases() : null;
		//
	}

	private static void load(final KeyStore instance, final InputStream stream, final char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		if (stream != null && stream.markSupported()) {
			//
			final byte[] bs = IOUtils.toByteArray(stream);
			//
			if (bs == null || bs.length == 0) {
				//
				return;
				//
			} // if
				//
			stream.reset();
			//
		} // if
			//
		instance.load(stream, password);
		//
	}

	private static boolean isValid(final DomainValidator instance, final String domain) {
		//
		if (instance == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "domainRegex")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field != null && Narcissus.getField(instance, field) == null) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(domain), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "value")), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(domain, field) == null) {
			//
			return false;
			//
		} // if
			//
		return domain != null && instance.isValid(domain);
		//
	}

	private static void disconnect(final HttpsURLConnection instance) {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "delegate")), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.disconnect();
			//
		} // if
			//
	}

	private static String longestCommonSubstring(final String a, final String b) {
		//
		int start = 0, max = 0;
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(stream(testAndApply(Objects::nonNull, getClass(a), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "value")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final boolean conditionA = or(field, Objects::isNull, f -> Narcissus.getField(a, f) != null);
		//
		final boolean conditionB = or(field, Objects::isNull,
				f -> and(b, Objects::nonNull, g -> Narcissus.getField(g, f) != null));
		//
		for (int i = 0; and(conditionA, (value, index) -> index < StringUtils.length(value), a, i); i++) {
			//
			for (int j = 0; and(conditionB, (value, index) -> index < StringUtils.length(value), b, j); j++) {
				//
				int x = 0;
				//
				while (a.charAt(i + x) == b.charAt(j + x)) {
					//
					x++;
					//
					if (((i + x) >= a.length()) || ((j + x) >= b.length())) {
						//
						break;
						//
					} // if
						//
				} // while
					//
				if (x > max) {
					//
					max = x;
					//
					start = i;
					//
				} // if
					//
			} // for
				//
		} // for
			//
		return conditionA ? StringUtils.substring(a, start, start + max) : null;
		//
	}

	private static <T> boolean and(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) && test(b, value);
	}

	private static <T> boolean or(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) || test(b, value);
	}

	private static <T> boolean and(final boolean condition, final ObjIntPredicate<T> objIntPredicate, final T value,
			final int integer) {
		return condition && objIntPredicate != null && objIntPredicate.test(value, integer);
	}

	private static String getName(final X500Principal instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "thisX500Name")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getName() : null;
		//
	}

	private static X500Principal getSubjectX500Principal(final X509Certificate instance) {
		return instance != null ? instance.getSubjectX500Principal() : null;
	}

	private static Certificate[] getServerCertificates(final HttpsURLConnection instance)
			throws SSLPeerUnverifiedException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "delegate")), Collectors.toList()),
				x -> get(x, 0), null);

		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getServerCertificates() : null;
		//
	}

	private static void connect(final HttpsURLConnection instance) throws IOException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "delegate")), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.connect();
			//
		} // if
			//
	}

	private static <T> T cast(final Class<T> clz, final Object instance) {
		return clz != null && clz.isInstance(instance) ? clz.cast(instance) : null;
	}

	private static URLConnection openConnection(final URL instance) throws IOException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "handler")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.openConnection() : null;
		//
	}

	private static <V> V get(final Map<?, V> instance, final Object key) {
		return instance != null ? instance.get(key) : null;
	}

	private static Map<String, String> toMap(final String... ss) {
		//
		Map<String, String> map = null;
		//
		Entry<String, String> entry = null;
		//
		for (int i = 0; i < length(ss); i++) {
			//
			if ((entry = toEntry(ArrayUtils.get(ss, i))) == null) {
				//
				continue;
				//
			} // if
				//
			put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), getKey(entry), getValue(entry));
			//
		} // for
			//
		return map;
		//
	}

	private static <K, V> void put(final Map<K, V> instance, final K key, final V value) {
		if (instance != null) {
			instance.put(key, value);
		}
	}

	private static int length(final Object[] instance) {
		return instance != null ? instance.length : 0;
	}

	private static <K> K getKey(final Entry<K, ?> instance) {
		return instance != null ? instance.getKey() : null;
	}

	private static <V> V getValue(final Entry<?, V> instance) {
		return instance != null ? instance.getValue() : null;
	}

	private static Entry<String, String> toEntry(final String string) {
		//
		Field field = null;
		//
		if (field == null) {
			//
			field = testAndApply(x -> size(x) == 1, collect(
					filter(stream(testAndApply(Objects::nonNull, getClass(string), FieldUtils::getAllFieldsList, null)),
							f -> Objects.equals(getName(f), "value")),
					Collectors.toList()), x -> get(x, 0), null);
			//
		} // if
			//
		if (string != null && field != null && Narcissus.getField(string, field) == null) {
			//
			return null;
			//
		} // if
			//
		if (Objects.equals(string, "=")) {
			//
			return Pair.of("", "");
			//
		} else if (string != null && string.length() == 2 && string.charAt(0) == '=') {
			//
			return Pair.of("", string.substring(1, string.length()));
			//
		} else if (string != null && string.length() == 2 && string.charAt(string.length() - 1) == '=') {
			//
			return Pair.of(string.substring(0, string.length() - 1), "");
			//
		} else if (string != null && string.indexOf('=') >= 0 && string.indexOf('=') == string.lastIndexOf('=')) {
			//
			return Pair.of(StringUtils.substringBefore(string, '='), StringUtils.substringAfter(string, '='));
			//
		} else if (string != null && string.length() > 2 && string.indexOf('=') != string.lastIndexOf('=')) {
			//
			return Pair.of(StringUtils.substring(string, 0, string.indexOf('=')),
					StringUtils.substring(string, string.indexOf('=') + 1));
			//
		} // if
			//
		return null;
		//
	}

	private static int size(final Collection<?> instance) {
		return instance != null ? instance.size() : 0;
	}

	private static <E> E get(final List<E> instance, final int index) {
		return instance != null ? instance.get(index) : null;
	}

	private static String getName(final Member instance) {
		return instance != null ? instance.getName() : null;
	}

	private static <T, R, A> R collect(final Stream<T> instance, final Collector<? super T, A, R> collector) {
		//
		return instance != null && (collector != null || Proxy.isProxyClass(getClass(instance)))
				? instance.collect(collector)
				: null;
		//
	}

	private static <T> Stream<T> filter(final Stream<T> instance, final Predicate<? super T> predicate) {
		return instance != null ? instance.filter(predicate) : instance;
	}

	private static <T> Stream<T> stream(final Collection<T> instance) {
		return instance != null ? instance.stream() : null;
	}

	private static <T, R, E extends Throwable> R testAndApply(final Predicate<T> predicate, final T value,
			final FailableFunction<T, R, E> functionTrue, final FailableFunction<T, R, E> functionFalse) throws E {
		return test(predicate, value) ? apply(functionTrue, value) : apply(functionFalse, value);
	}

	private static <T, R, E extends Throwable> R apply(final FailableFunction<T, R, E> instance, final T value)
			throws E {
		return instance != null ? instance.apply(value) : null;
	}

	private static <T> boolean test(final Predicate<T> instance, final T value) {
		return instance != null && instance.test(value);
	}

	private static Class<?> getClass(final Object instance) {
		return instance != null ? instance.getClass() : null;
	}

}