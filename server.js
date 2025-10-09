import React, {
  useEffect,
  useMemo,
  useState,
  useRef,
} from 'react';
import {
  SafeAreaView,
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Switch,
  ActivityIndicator,
  Alert,
  Platform,
  Animated,
  Easing,
  Image,
  StyleSheet,
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as LocalAuthentication from 'expo-local-authentication';
import axios from 'axios';

/* ========= CONFIG ========= */
// LIVE backend (change only if you renamed it)
const API_URL = 'https://caribpay-backend-mini.onrender.com';

// Storage keys
const TOKEN_KEY = 'caribpay_token';
const EMAIL_KEY = 'caribpay_email';
const REMEMBER_KEY = 'caribpay_remember';

// Theme
const COLORS = {
  bg: '#0A0F10',
  text: '#FFFFFF',
  sub: '#9ecfd3',
  green: '#009E49',
  yellow: '#FCD116',
  red: '#CE1126',
  inputBg: '#13252b',
  disabled: '#334455',
};

// Hosted images (so you don’t need uploads on iPad)
const LOGO_URL =
  'https://files.oaiusercontent.com/file-000000003b00622fb06b2925000b90ef-A_vector_logo_design_features_the_brand_name_Cari.png';
const ICON_URL =
  'https://files.oaiusercontent.com/file-000000008270622f8fd391bf8ba75714-A_logo_for_CaribPay_is_displayed_in_a_digital_vect.png';
const SPLASH_URL =
  'https://files.oaiusercontent.com/file-0000000035a861f58a82adf36b8cbb5a-A_logo_for_CaribPay_is_centered_on_a_solid_black.png';

/* ========= Animated Brand Logo ========= */
function BrandMarkAnimated() {
  const opacity = useRef(new Animated.Value(0)).current;
  const translateY = useRef(new Animated.Value(8)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(opacity, {
        toValue: 1,
        duration: 700,
        easing: Easing.out(Easing.cubic),
        useNativeDriver: true,
      }),
      Animated.timing(translateY, {
        toValue: 0,
        duration: 700,
        easing: Easing.out(Easing.cubic),
        useNativeDriver: true,
      }),
    ]).start();
  }, []);

  return (
    <Animated.View
      style={{
        opacity,
        transform: [{ translateY }],
        alignItems: 'center',
        marginTop: 36,
        marginBottom: 14,
      }}
    >
      <Image
        source={{ uri: LOGO_URL }}
        style={{ width: 140, height: 140, resizeMode: 'contain' }}
      />
    </Animated.View>
  );
}

/* ========= Little header with the Rasta stripe ========= */
function Header({ title = 'CaribPay' }) {
  return (
    <View style={{ marginBottom: 18 }}>
      <Text style={{ color: COLORS.text, fontSize: 28, fontWeight: '900' }}>
        {title}
      </Text>
      <View style={{ flexDirection: 'row', marginTop: 10 }}>
        <View style={styles.stripeLeft} />
        <View style={styles.stripeMid} />
        <View style={styles.stripeRight} />
      </View>
    </View>
  );
}

/* ========= Reusable UI ========= */
function Input({ placeholder, secure, value, onChangeText, right, autoCapitalize='none' }) {
  return (
    <View style={styles.inputWrap}>
      <TextInput
        placeholder={placeholder}
        placeholderTextColor="#6b8a92"
        value={value}
        onChangeText={onChangeText}
        secureTextEntry={secure}
        style={styles.input}
        autoCapitalize={autoCapitalize}
      />
      {right}
    </View>
  );
}

function Button({ title, onPress, disabled, busy }) {
  return (
    <TouchableOpacity
      onPress={onPress}
      disabled={disabled || busy}
      style={[
        styles.btn,
        disabled ? { backgroundColor: COLORS.disabled } : null,
      ]}
    >
      {busy ? (
        <ActivityIndicator color="#fff" />
      ) : (
        <Text style={styles.btnText}>{title}</Text>
      )}
    </TouchableOpacity>
  );
}

/* ========= Main App (login/register/welcome) ========= */
export default function App() {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);

  const [token, setToken] = useState<string | null>(null);
  const [signedEmail, setSignedEmail] = useState<string | null>(null);

  // On launch: check existing session
  useEffect(() => {
    (async () => {
      const saved = await SecureStore.getItemAsync(TOKEN_KEY);
      const savedEmail = await SecureStore.getItemAsync(EMAIL_KEY);
      const rememberStr = await SecureStore.getItemAsync(REMEMBER_KEY);
      if (rememberStr) setRemember(rememberStr === '1');
      if (saved && savedEmail) {
        setToken(saved);
        setSignedEmail(savedEmail);
      }
    })();
  }, []);

  // FaceID quick auth when remember is on and we have a stored token
  useEffect(() => {
    (async () => {
      const saved = await SecureStore.getItemAsync(TOKEN_KEY);
      const savedEmail = await SecureStore.getItemAsync(EMAIL_KEY);
      if (remember && saved && savedEmail) {
        const hasHardware = await LocalAuthentication.hasHardwareAsync();
        const enrolled = await LocalAuthentication.isEnrolledAsync();
        if (hasHardware && enrolled) {
          const res = await LocalAuthentication.authenticateAsync({
            promptMessage: 'Unlock CaribPay',
          });
          if (res.success) {
            setToken(saved);
            setSignedEmail(savedEmail);
          }
        }
      }
    })();
  }, [remember]);

  async function handleAuth() {
    setBusy(true);
    try {
      const endpoint =
        mode === 'login' ? '/api/auth/login' : '/api/auth/register';

      const { data } = await axios.post(`${API_URL}${endpoint}`, {
        email,
        password,
      });

      if (!data?.token) {
        throw new Error('No token returned from server.');
      }

      await SecureStore.setItemAsync(TOKEN_KEY, data.token);
      await SecureStore.setItemAsync(EMAIL_KEY, email);
      await SecureStore.setItemAsync(REMEMBER_KEY, remember ? '1' : '0');

      setToken(data.token);
      setSignedEmail(email);

      if (mode === 'register') {
        Alert.alert('Success', 'Account created. You are signed in. 🎉');
      }
    } catch (e) {
      console.log(e);
      Alert.alert(
        mode === 'login' ? 'Sign in failed' : 'Sign up failed',
        'Please check your details and try again.'
      );
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    await SecureStore.deleteItemAsync(TOKEN_KEY);
    setToken(null);
    setSignedEmail(null);
    setEmail('');
    setPassword('');
  }

  // === If signed in, show Welcome screen
  if (token) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={{ padding: 20 }}>
          <BrandMarkAnimated />
          <Header title="Welcome 🇬🇩" />
          <View style={styles.card}>
            <Text style={{ color: COLORS.sub, marginBottom: 6 }}>
              Signed in as
            </Text>
            <Text style={{ color: COLORS.text, fontWeight: '700', fontSize: 16 }}>
              {signedEmail}
            </Text>
          </View>
          <Button title="Sign out" onPress={signOut} />
        </View>
      </SafeAreaView>
    );
  }

  // === Auth screen (login/register)
  return (
    <SafeAreaView style={styles.container}>
      <View style={{ padding: 20 }}>
        <BrandMarkAnimated />
        <Header title="CaribPay" />

        <Input
          placeholder="Email"
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
        />

        <Input
          placeholder="Password"
          value={password}
          onChangeText={setPassword}
          secure
          right={
            <Text style={{ color: COLORS.sub, marginRight: 10 }}>
              {password ? '• • •' : ''}
            </Text>
          }
        />

        <View style={styles.row}>
          <Text style={{ color: COLORS.sub }}>Remember me / Face ID</Text>
          <Switch
            value={remember}
            onValueChange={setRemember}
            thumbColor={remember ? COLORS.green : '#ccc'}
          />
        </View>

        <Button
          title={mode === 'login' ? 'Sign in' : 'Create account'}
          onPress={handleAuth}
          busy={busy}
          disabled={!email || !password}
        />

        <TouchableOpacity
          onPress={() => setMode(mode === 'login' ? 'register' : 'login')}
          style={{ marginTop: 14, alignSelf: 'center' }}
        >
          <Text style={{ color: COLORS.sub }}>
            {mode === 'login' ? 'Create an account' : 'Back to sign in'}
          </Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

/* ========= Styles ========= */
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.bg },
  inputWrap: {
    backgroundColor: COLORS.inputBg,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
    marginBottom: 12,
    flexDirection: 'row',
    alignItems: 'center',
  },
  input: {
    color: COLORS.text,
    fontSize: 16,
    flex: 1,
  },
  btn: {
    backgroundColor: COLORS.red,
    paddingVertical: 14,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 8,
    marginBottom: 8,
  },
  btnText: {
    color: 'white',
    fontWeight: '700',
    fontSize: 16,
  },
  row: {
    marginTop: 8,
    marginBottom: 8,
    paddingVertical: 6,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  stripeLeft: {
    height: 6, flex: 1, backgroundColor: COLORS.red,
    borderTopLeftRadius: 4, borderBottomLeftRadius: 4,
  },
  stripeMid: { height: 6, flex: 1, backgroundColor: COLORS.yellow },
  stripeRight: {
    height: 6, flex: 1, backgroundColor: COLORS.green,
    borderTopRightRadius: 4, borderBottomRightRadius: 4,
  },
  card: {
    backgroundColor: '#0f1b20',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
  },
});
