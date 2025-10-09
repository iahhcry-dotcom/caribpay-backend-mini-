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
  Platform,
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as LocalAuthentication from 'expo-local-authentication';
import axios from 'axios';

/* ======== CONFIG ======== */
const API_URL = 'https://caribpay-backend-mini.onrender.com'; // live backend
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

/* ======== MAIN APP ======== */
function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  const [loading, setLoading] = useState(false);
  const [faceIdEnabled, setFaceIdEnabled] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userEmail, setUserEmail] = useState('');

  useEffect(() => {
    loadRememberedUser();
  }, []);

  async function loadRememberedUser() {
    const remembered = await SecureStore.getItemAsync(REMEMBER_KEY);
    if (remembered) {
      const creds = JSON.parse(remembered);
      setEmail(creds.email);
      setPassword(creds.password);
      setFaceIdEnabled(true);
      tryFaceIdLogin(creds.email, creds.password);
    }
  }

  async function tryFaceIdLogin(email, password) {
    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    const supported = await LocalAuthentication.supportedAuthenticationTypesAsync();
    if (hasHardware && supported.length) {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Login with Face ID',
      });
      if (result.success) handleLogin(email, password);
    }
  }

  async function handleLogin(loginEmail = email, loginPassword = password) {
    if (!loginEmail || !loginPassword) return Alert.alert('Missing info', 'Please enter all fields.');
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/api/auth/login`, {
        email: loginEmail,
        password: loginPassword,
      });
      await SecureStore.setItemAsync(TOKEN_KEY, res.data.token);
      if (faceIdEnabled)
        await SecureStore.setItemAsync(REMEMBER_KEY, JSON.stringify({ email: loginEmail, password: loginPassword }));
      setUserEmail(loginEmail);
      setIsLoggedIn(true);
    } catch (err) {
      Alert.alert('Login failed', err.response?.data?.error || 'Server error');
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister() {
    if (!email || !password) return Alert.alert('Missing info', 'Please enter all fields.');
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/api/auth/register`, { email, password });
      await SecureStore.setItemAsync(TOKEN_KEY, res.data.token);
      setUserEmail(email);
      setIsLoggedIn(true);
    } catch (err) {
      Alert.alert('Sign up failed', err.response?.data?.error || 'Server error');
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    await SecureStore.deleteItemAsync(TOKEN_KEY);
    setIsLoggedIn(false);
    setEmail('');
    setPassword('');
  }

  if (loading)
    return (
      <SafeAreaView style={{ flex: 1, backgroundColor: COLORS.bg, justifyContent: 'center', alignItems: 'center' }}>
        <ActivityIndicator size="large" color={COLORS.green} />
        <Text style={{ color: COLORS.text, marginTop: 10 }}>Loading...</Text>
      </SafeAreaView>
    );

  if (isLoggedIn)
    return (
      <SafeAreaView style={{ flex: 1, backgroundColor: COLORS.bg, justifyContent: 'center', alignItems: 'center' }}>
        <View style={{ height: 5, width: '100%', backgroundColor: COLORS.red }} />
        <View style={{ height: 5, width: '100%', backgroundColor: COLORS.yellow }} />
        <View style={{ height: 5, width: '100%', backgroundColor: COLORS.green }} />
        <Text style={{ color: COLORS.text, fontSize: 24, fontWeight: 'bold', marginTop: 40 }}>
          Welcome 🇬🇩
        </Text>
        <Text style={{ color: COLORS.sub, marginTop: 10 }}>Signed in as</Text>
        <Text style={{ color: COLORS.text, fontWeight: '600', marginVertical: 8 }}>{userEmail}</Text>
        <TouchableOpacity
          onPress={handleLogout}
          style={{
            marginTop: 30,
            backgroundColor: COLORS.red,
            paddingVertical: 12,
            paddingHorizontal: 40,
            borderRadius: 8,
          }}
        >
          <Text style={{ color: COLORS.text, fontWeight: 'bold' }}>Sign out</Text>
        </TouchableOpacity>
      </SafeAreaView>
    );

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: COLORS.bg, padding: 20 }}>
      <View style={{ height: 5, backgroundColor: COLORS.red }} />
      <View style={{ height: 5, backgroundColor: COLORS.yellow }} />
      <View style={{ height: 5, backgroundColor: COLORS.green }} />

      <View style={{ flex: 1, justifyContent: 'center' }}>
        <Text style={{ color: COLORS.text, fontSize: 28, fontWeight: 'bold', marginBottom: 20 }}>CaribPay</Text>

        <TextInput
          placeholder="Email"
          placeholderTextColor={COLORS.sub}
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          keyboardType="email-address"
          style={{
            backgroundColor: COLORS.inputBg,
            color: COLORS.text,
            borderRadius: 8,
            padding: 12,
            marginBottom: 12,
          }}
        />
        <TextInput
          placeholder="Password"
          placeholderTextColor={COLORS.sub}
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          style={{
            backgroundColor: COLORS.inputBg,
            color: COLORS.text,
            borderRadius: 8,
            padding: 12,
            marginBottom: 12,
          }}
        />

        <View style={{ flexDirection: 'row', alignItems: 'center', marginVertical: 8 }}>
          <Switch value={faceIdEnabled} onValueChange={setFaceIdEnabled} />
          <Text style={{ color: COLORS.text, marginLeft: 8 }}>Remember me / Face ID</Text>
        </View>

        <TouchableOpacity
          onPress={mode === 'login' ? handleLogin : handleRegister}
          style={{
            backgroundColor: COLORS.yellow,
            borderRadius: 8,
            paddingVertical: 14,
            marginTop: 10,
            alignItems: 'center',
          }}
        >
          <Text style={{ color: COLORS.bg, fontWeight: 'bold', fontSize: 16 }}>
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity onPress={() => setMode(mode === 'login' ? 'register' : 'login')}>
          <Text
            style={{
              color: COLORS.sub,
              textAlign: 'center',
              marginTop: 16,
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
