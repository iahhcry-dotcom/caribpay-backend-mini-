import React, { useEffect, useMemo, useState, createContext, useContext } from 'react';
import { SafeAreaView, View, Text, TextInput, TouchableOpacity, Switch, ActivityIndicator, Alert, Platform } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as LocalAuthentication from 'expo-local-authentication';
import axios from 'axios';

// ======= CONFIG =======
const API_URL = 'https://caribpay-backend-mini.onrender.com'; // your live backend
const TOKEN_KEY = 'caribpay_token';
const REMEMBER_KEY = 'caribpay_remember';

// Island theme (Grenada colors)
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

// Axios (60s for Render cold start)
const api = axios.create({ baseURL: API_URL, timeout: 60000 });
api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.data?.message) err.message = err.response.data.message;
    return Promise.reject(err);
  }
);

// ======= AUTH CONTEXT =======
const AuthCtx = createContext(null);
const useAuth = () => useContext(AuthCtx);

function AuthProvider({ children }) {
  const [token, setToken] = useState(null);
  const [booting, setBooting] = useState(true);

  const saveToken = (t) => SecureStore.setItemAsync(TOKEN_KEY, t);
  const getToken = () => SecureStore.getItemAsync(TOKEN_KEY);
  const clearToken = () => SecureStore.deleteItemAsync(TOKEN_KEY);
  const setRemember = (v) => SecureStore.setItemAsync(REMEMBER_KEY, v ? '1' : '0');
  const getRemember = async () => (await SecureStore.getItemAsync(REMEMBER_KEY)) === '1';

  const signIn = async (email, password, remember) => {
    const { data } = await api.post('/auth/login', { email, password });
    setToken(data.token);
    await saveToken(data.token);
    await setRemember(remember);
  };

  const register = async (email, password, remember) => {
    const { data } = await api.post('/auth/register', { email, password });
    setToken(data.token);
    await saveToken(data.token);
    await setRemember(remember);
  };

  const signOut = async () => {
    setToken(null);
    await clearToken();
    await setRemember(false);
  };

  const tryAutoLogin = async () => {
    const remember = await getRemember();
    if (!remember) return false;
    const hasHw = await LocalAuthentication.hasHardwareAsync();
    const enrolled = await LocalAuthentication.isEnrolledAsync();
    if (!hasHw || !enrolled) return false;
    const res = await LocalAuthentication.authenticateAsync({ promptMessage: 'Unlock CaribPay' });
    if (!res.success) return false;
    const t = await getToken();
    if (!t) return false;
    setToken(t);
    return true;
  };

  useEffect(() => { (async () => { try { await tryAutoLogin(); } finally { setBooting(false); } })(); }, []);

  const value = useMemo(() => ({ token, signIn, register, signOut }), [token]);
  if (booting) return <FullScreen><ActivityIndicator /></FullScreen>;
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

// ======= UI HELPERS =======
function FullScreen({ children }) {
  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: COLORS.bg }}>
      <View style={{ height: 6, backgroundColor: COLORS.red }} />
      <View style={{ height: 6, backgroundColor: COLORS.yellow }} />
      <View style={{ height: 6, backgroundColor: COLORS.green, marginBottom: 6 }} />
      <View style={{ flex: 1, padding: 20, justifyContent: 'center' }}>{children}</View>
    </SafeAreaView>
  );
}
function Button({ title, onPress, disabled, style, color='green' }) {
  const bg = color === 'red' ? COLORS.red : color === 'yellow' ? COLORS.yellow : COLORS.green;
  return (
    <TouchableOpacity onPress={onPress} disabled={disabled}
      style={[{ backgroundColor: disabled ? COLORS.disabled : bg, padding: 16, borderRadius: 12, alignItems: 'center' }, style]}>
      <Text style={{ color: 'white', fontWeight: '700' }}>{title}</Text>
    </TouchableOpacity>
  );
}
function Link({ title, onPress }) {
  return (
    <TouchableOpacity onPress={onPress} style={{ alignSelf: 'center', marginTop: 14 }}>
      <Text style={{ color: COLORS.sub, textDecorationLine: 'underline' }}>{title}</Text>
    </TouchableOpacity>
  );
}
function Input({
  value, onChangeText, placeholder, secureTextEntry, keyboardType, autoCapitalize='none',
  right, // optional trailing component
}) {
  return (
    <View style={{
      backgroundColor: COLORS.inputBg, borderRadius: 12, paddingHorizontal: 14,
      paddingVertical: Platform.OS === 'ios' ? 14 : 10, marginBottom: 12, flexDirection: 'row', alignItems: 'center'
    }}>
      <TextInput
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder}
        placeholderTextColor="#6f8a93"
        secureTextEntry={secureTextEntry}
        keyboardType={keyboardType}
        autoCapitalize={autoCapitalize}
        autoCorrect={false}
        style={{ color: COLORS.text, fontSize: 16, flex: 1 }}
      />
      {right}
    </View>
  );
}
function LoadingOverlay({ text }) {
  return (
    <View style={{ position: 'absolute', left:0, right:0, top:0, bottom:0, justifyContent:'center', alignItems:'center' }}>
      <ActivityIndicator />
      <Text style={{ color: COLORS.sub, marginTop: 10 }}>{text}</Text>
    </View>
  );
}

// Wake the server (Render free tier)
async function wakeServer() { return (await api.get('/')).data; }

// ======= SCREENS =======
function LoginScreen({ goRegister }) {
  const { signIn } = useAuth();
  // Smooth typing: keep controlled state; sanitize email on change (no spaces)
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [remember, setRemember] = useState(true);
  const [waking, setWaking] = useState(false);
  const [loading, setLoading] = useState(false);

  const onEmailChange = (t) => setEmail(t.replace(/\s/g, '').toLowerCase()); // block spaces
  const onSubmit = async () => {
    try { setWaking(true); await wakeServer(); } catch {} finally { setWaking(false); }
    try { setLoading(true); await signIn(email.trim(), password, remember); }
    catch (e) { Alert.alert('Login failed', e.message || 'Please try again.'); }
    finally { setLoading(false); }
  };
  const busy = waking || loading;

  return (
    <FullScreen>
      <Header />
      <Input value={email} onChangeText={onEmailChange} placeholder="Email" keyboardType="email-address" />
      <Input
        value={password}
        onChangeText={setPassword}
        placeholder="Password"
        secureTextEntry={!showPass}
        right={
          <TouchableOpacity onPress={() => setShowPass(s => !s)}>
            <Text style={{ color: COLORS.sub, fontWeight: '700' }}>{showPass ? 'HIDE' : 'SHOW'}</Text>
          </TouchableOpacity>
        }
      />
      <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 16 }}>
        <Switch value={remember} onValueChange={setRemember} />
        <Text style={{ color: COLORS.text, marginLeft: 10 }}>Remember me / Face ID</Text>
      </View>
      <Button title={busy ? 'Signing in…' : 'Sign in'} onPress={onSubmit} disabled={busy || !email || !password} />
      <Link title="Create an account" onPress={goRegister} />
      {busy && <LoadingOverlay text={waking ? 'Waking server…' : 'Signing you in…'} />}
    </FullScreen>
  );
}

function RegisterScreen({ goLogin }) {
  const { register } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [remember, setRemember] = useState(true);
  const [waking, setWaking] = useState(false);
  const [loading, setLoading] = useState(false);

  const onEmailChange = (t) => setEmail(t.replace(/\s/g, '').toLowerCase()); // block spaces in email
  const onSubmit = async () => {
    if (password.length < 6) return Alert.alert('Weak password', 'Use at least 6 characters.');
    if (password !== confirm) return Alert.alert('Passwords do not match', 'Please confirm your password.');
    try { setWaking(true); await wakeServer(); } catch {} finally { setWaking(false); }
    try { setLoading(true); await register(email.trim(), password, remember); }
    catch (e) { Alert.alert('Sign up failed', e.message || 'Please try again.'); }
    finally { setLoading(false); }
  };
  const busy = waking || loading;

  return (
    <FullScreen>
      <Header title="Create Account" />
      <Input value={email} onChangeText={onEmailChange} placeholder="Email" keyboardType="email-address" />
      <Input
        value={password}
        onChangeText={setPassword}
        placeholder="Password (min 6)"
        secureTextEntry={!showPass}
        right={
          <TouchableOpacity onPress={() => setShowPass(s => !s)}>
            <Text style={{ color: COLORS.sub, fontWeight: '700' }}>{showPass ? 'HIDE' : 'SHOW'}</Text>
          </TouchableOpacity>
        }
      />
      <Input value={confirm} onChangeText={setConfirm} placeholder="Confirm password" secureTextEntry={!showPass} />
      <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 16 }}>
        <Switch value={remember} onValueChange={setRemember} />
        <Text style={{ color: COLORS.text, marginLeft: 10 }}>Remember me / Face ID</Text>
      </View>
      <Button title={busy ? 'Creating…' : 'Create account'} onPress={onSubmit} disabled={busy || !email || !password || !confirm} color="yellow" />
      <Link title="Back to sign in" onPress={goLogin} />
      {busy && <LoadingOverlay text={waking ? 'Waking server…' : 'Creating your account…'} />}
    </FullScreen>
  );
}

function HomeScreen() {
  const { token, signOut } = useAuth();
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { (async () => {
    try {
      const { data } = await api.get('/auth/me', { headers: { Authorization: `Bearer ${token}` } });
      setMe(data);
    } catch (e) {
      Alert.alert('Session', e.message || 'Could not load profile');
    } finally { setLoading(false); }
  })(); }, [token]);

  return (
    <FullScreen>
      {loading ? <ActivityIndicator /> : (
        <>
          <Header title="Welcome 🇬🇩" />
          <View style={{ backgroundColor: COLORS.inputBg, borderRadius: 12, padding: 16, marginBottom: 20 }}>
            <Text style={{ color: COLORS.sub, marginBottom: 6 }}>Signed in as</Text>
            <Text style={{ color: COLORS.text, fontSize: 18, fontWeight: '700' }}>{me ? me.email : 'Unknown user'}</Text>
          </View>
          <Button title="Sign out" onPress={signOut} color="red" />
        </>
      )}
    </FullScreen>
  );
}

function Header({ title = 'CaribPay' }) {
  return (
    <View style={{ marginBottom: 20 }}>
      <Text style={{ color: COLORS.text, fontSize: 30, fontWeight: '900' }}>{title}</Text>
      <View style={{ flexDirection: 'row', marginTop: 10 }}>
        <View style={{ height: 6, flex: 1, backgroundColor: COLORS.red, borderTopLeftRadius: 4, borderBottomLeftRadius: 4 }} />
        <View style={{ height: 6, flex: 1, backgroundColor: COLORS.yellow }} />
        <View style={{ height: 6, flex: 1, backgroundColor: COLORS.green, borderTopRightRadius: 4, borderBottomRightRadius: 4 }} />
      </View>
    </View>
  );
}

// ======= ROOT =======
function InnerApp() {
  const { token } = useAuth();
  const [mode, setMode] = useState('login'); // 'login' | 'register'
  if (token) return <HomeScreen />;
  return mode === 'login'
    ? <LoginScreen goRegister={() => setMode('register')} />
    : <RegisterScreen goLogin={() => setMode('login')} />;
}

export default function App() {
  return (
    <AuthProvider>
      <InnerApp />
    </AuthProvider>
  );
}
