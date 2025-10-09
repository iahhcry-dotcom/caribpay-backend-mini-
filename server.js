import React, { useEffect, useState } from 'react';
import {
  SafeAreaView,
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Switch,
  ActivityIndicator,
  Alert,
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as LocalAuthentication from 'expo-local-authentication';
import axios from 'axios';

/* ======== CONFIG ======== */
const API_URL = 'https://caribpay-backend-mini.onrender.com'; // your live backend
const TOKEN_KEY = 'caribpay_token';
const REMEMBER_KEY = 'caribpay_remember';

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

/* ======== UI HELPERS ======== */
function Bar() {
  return (
    <View>
      <View style={{ height: 5, backgroundColor: COLORS.red }} />
      <View style={{ height: 5, backgroundColor: COLORS.yellow }} />
      <View style={{ height: 5, backgroundColor: COLORS.green }} />
    </View>
  );
}

function Field({ placeholder, value, onChangeText, secure }) {
  return (
    <TextInput
      placeholder={placeholder}
      placeholderTextColor={COLORS.sub}
      value={value}
      onChangeText={onChangeText}
      secureTextEntry={secure}
      autoCapitalize="none"
      style={{
        backgroundColor: COLORS.inputBg,
        color: COLORS.text,
        borderRadius: 10,
        padding: 14,
        marginBottom: 12,
        fontSize: 16,
      }}
    />
  );
}

function Btn({ title, onPress, disabled, color }) {
  return (
    <TouchableOpacity
      onPress={onPress}
      disabled={disabled}
      style={{
        backgroundColor: disabled ? COLORS.disabled : (color || COLORS.yellow),
        borderRadius: 10,
        paddingVertical: 14,
        alignItems: 'center',
        marginTop: 8,
      }}
    >
      <Text style={{ color: disabled ? '#ced6db' : COLORS.bg, fontWeight: '800', fontSize: 16 }}>
        {title}
      </Text>
    </TouchableOpacity>
  );
}

/* ======== APP ======== */
function App() {
  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);

  const [token, setToken] = useState(null);
  const [signedEmail, setSignedEmail] = useState(null);

  const [health, setHealth] = useState<'ok' | 'down' | 'checking'>('checking');

  // --- Health check on boot
  useEffect(() => {
    (async () => {
      try {
        // You can add this route in your server to return {ok:true}; if missing, fall back to '/'
        const res = await fetch(`${API_URL}/api/auth/test`).catch(() => null);
        if (res && res.ok) setHealth('ok');
        else {
          const ping = await fetch(`${API_URL}/`).catch(() => null);
          setHealth(ping && ping.ok ? 'ok' : 'down');
        }
      } catch {
        setHealth('down');
      }
    })();
  }, []);

  // --- Restore session / Face ID
  useEffect(() => {
    (async () => {
      const savedToken = await SecureStore.getItemAsync(TOKEN_KEY);
      const savedRemember = await SecureStore.getItemAsync(REMEMBER_KEY);
      if (savedRemember) {
        const data = JSON.parse(savedRemember);
        setEmail(data.email || '');
        setPassword(data.password || '');
        setRemember(true);

        const hasHw = await LocalAuthentication.hasHardwareAsync();
        const enrolled = await LocalAuthentication.isEnrolledAsync();
        if (hasHw && enrolled) {
          const res = await LocalAuthentication.authenticateAsync({ promptMessage: 'Unlock CaribPay' });
          if (res.success && savedToken) {
            setToken(savedToken);
            setSignedEmail(data.email || '');
          }
        }
      } else if (savedToken) {
        setToken(savedToken);
        setSignedEmail('user');
      }
    })();
  }, []);

  function showServerError(err, fallback) {
    const msg =
      err?.response?.data?.error ||
      err?.message ||
      fallback ||
      'Server error';
    Alert.alert(mode === 'login' ? 'Login failed' : 'Sign up failed', msg);
  }

  async function auth(endpoint) {
    if (!email || !password) return Alert.alert('Missing info', 'Please enter email and password.');
    setBusy(true);
    try {
      const { data } = await axios.post(`${API_URL}${endpoint}`, { email, password });
      if (!data?.token) throw new Error('No token returned');
      await SecureStore.setItemAsync(TOKEN_KEY, data.token);
      if (remember) await SecureStore.setItemAsync(REMEMBER_KEY, JSON.stringify({ email, password }));
      setToken(data.token);
      setSignedEmail(email);
    } catch (err) {
      showServerError(err);
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    await SecureStore.deleteItemAsync(TOKEN_KEY);
    setToken(null);
    setSignedEmail(null);
    if (!remember) {
      await SecureStore.deleteItemAsync(REMEMBER_KEY);
      setEmail('');
      setPassword('');
    }
  }

  // ---------- Screens ----------
  if (busy) {
    return (
      <SafeAreaView style={{ flex: 1, backgroundColor: COLORS.bg, justifyContent: 'center', alignItems: 'center' }}>
        <ActivityIndicator size="large" color={COLORS.green} />
        <Text style={{ color: COLORS.text, marginTop: 10 }}>Loading…</Text>
      </SafeAreaView>
    );
  }

  if (token) {
    return (
      <SafeAreaView style={{ flex: 1, backgroundColor: COLORS.bg }}>
        <Bar />
        <View style={{ flex: 1, padding: 20, justifyContent: 'center' }}>
          <Text style={{ color: COLORS.text, fontSize: 28, fontWeight: '900', marginBottom: 10 }}>
            Welcome 🇬🇩
          </Text>
          <View style={{ backgroundColor: '#102027', padding: 16, borderRadius: 12, marginBottom: 16 }}>
            <Text style={{ color: COLORS.sub, marginBottom: 6 }}>Signed in as</Text>
            <Text style={{ color: COLORS.text, fontWeight: '700' }}>{signedEmail}</Text>
          </View>
          <Btn title="Sign out" onPress={signOut} color={COLORS.red} />
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: COLORS.bg }}>
      <Bar />
      {health === 'down' && (
        <View style={{ backgroundColor: '#8b1b1b', padding: 10 }}>
          <Text style={{ color: '#fff', textAlign: 'center' }}>
            Server offline — open the app again in 30–60s or redeploy on Render
          </Text>
        </View>
      )}

      <View style={{ flex: 1, padding: 20, justifyContent: 'center' }}>
        <Text style={{ color: COLORS.text, fontSize: 30, fontWeight: '900', marginBottom: 16 }}>CaribPay</Text>

        <Field placeholder="Email" value={email} onChangeText={setEmail} />
        <Field placeholder="Password" value={password} onChangeText={setPassword} secure />

        <View style={{ flexDirection: 'row', alignItems: 'center', marginVertical: 8 }}>
          <Switch value={remember} onValueChange={setRemember} />
          <Text style={{ color: COLORS.text, marginLeft: 8 }}>Remember me / Face ID</Text>
        </View>

        <Btn
          title={mode === 'login' ? 'Sign in' : 'Create account'}
          onPress={() => auth(mode === 'login' ? '/api/auth/login' : '/api/auth/register')}
          disabled={!email || !password || health === 'down'}
        />

        <TouchableOpacity onPress={() => setMode(mode === 'login' ? 'register' : 'login')}>
          <Text
            style={{
              color: COLORS.sub,
              textAlign: 'center',
              marginTop: 14,
              textDecorationLine: 'underline',
            }}
          >
            {mode === 'login' ? 'Create an account' : 'Back to sign in'}
          </Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

export default App;
