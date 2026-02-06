'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Form, Input, Button, Typography, App } from 'antd';
import { LockOutlined, MailOutlined } from '@ant-design/icons';
import { useAuthStore } from '@/store/provider';
import { api, APIError } from '@/lib/api';
import { colors } from '@/lib/theme';
import { C2Panel } from '@/components/c2';

const { Title, Text } = Typography;

interface LoginForm {
  email: string;
  password: string;
}

interface LoginResponse {
  access_token: string;
  refresh_token: string;
  user: {
    user_id: string;
    email: string;
    roles: string[];
  };
}

/**
 * Login page
 */
export default function LoginPage() {
  const router = useRouter();
  const { message } = App.useApp();
  const [loading, setLoading] = useState(false);
  
  const setUser = useAuthStore((state) => state.setUser);
  const setTokens = useAuthStore((state) => state.setTokens);
  
  const handleLogin = async (values: LoginForm) => {
    setLoading(true);
    
    try {
      const response = await api.post<LoginResponse>('/api/v1/auth/login', values);
      
      setTokens(response.access_token, response.refresh_token);
      setUser(response.user);
      
      message.success('Login successful');
      router.push('/dashboard');
      
    } catch (error) {
      const msg =
        error instanceof APIError
          ? error.message
          : error instanceof Error
            ? error.message
            : String(error);
      const display =
        msg.includes('fetch') || msg.includes('Network') || msg.includes('CORS')
          ? 'Cannot reach API. Ensure the API is running and CORS allows this origin.'
          : msg || 'Login failed. Please try again.';
      message.error(display);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div
      className="auth-page"
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        backgroundColor: colors.bg.primary,
        padding: 16,
      }}
    >
      <C2Panel
        title="PROJECT ARC"
        style={{ width: '100%', maxWidth: 400 }}
      >
        <div className="font-mono" style={{ textAlign: 'center', marginBottom: 24, fontSize: 11, letterSpacing: '0.08em', color: colors.text.muted }}>
          SIGN IN
        </div>

        <Form
          name="login"
          onFinish={handleLogin}
          layout="vertical"
          requiredMark={false}
        >
          <Form.Item
            label="Email"
            name="email"
            rules={[
              { required: true, message: 'Email is required' },
              { type: 'email', message: 'Invalid email address' },
            ]}
          >
            <Input
              prefix={<MailOutlined style={{ color: colors.text.muted }} />}
              placeholder="Email"
              size="large"
              autoComplete="email"
            />
          </Form.Item>
          
          <Form.Item
            label="Password"
            name="password"
            rules={[
              { required: true, message: 'Password is required' },
              { min: 8, message: 'Password must be at least 8 characters' },
            ]}
          >
            <Input.Password
              prefix={<LockOutlined style={{ color: colors.text.muted }} />}
              placeholder="Password"
              size="large"
              autoComplete="current-password"
            />
          </Form.Item>
          
          <Form.Item style={{ marginBottom: 16 }}>
            <Button
              type="primary"
              htmlType="submit"
              loading={loading}
              block
              size="large"
            >
              Sign In
            </Button>
          </Form.Item>
        </Form>
        
        <div style={{ textAlign: 'center', marginBottom: 16 }}>
          <Text type="secondary">
            Don&apos;t have an account?{' '}
            <Link href="/register" style={{ color: colors.accent.primary }}>
              Create one
            </Link>
          </Text>
        </div>
        
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 12 }}>
            Enterprise Autonomous AI Red Team Framework
          </Text>
        </div>
      </C2Panel>
    </div>
  );
}
