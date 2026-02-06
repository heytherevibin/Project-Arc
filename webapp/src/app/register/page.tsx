'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Form, Input, Button, Typography, App } from 'antd';
import { LockOutlined, MailOutlined, UserOutlined } from '@ant-design/icons';
import { useAuthStore } from '@/store/provider';
import { api, APIError } from '@/lib/api';
import { colors } from '@/lib/theme';
import { C2Panel } from '@/components/c2';

const { Title, Text } = Typography;

interface RegisterForm {
  name: string;
  email: string;
  password: string;
  confirmPassword: string;
}

interface RegisterResponse {
  access_token: string;
  refresh_token: string;
  user: {
    user_id: string;
    email: string;
    name: string;
    roles: string[];
  };
}

/**
 * Registration page
 */
export default function RegisterPage() {
  const router = useRouter();
  const { message } = App.useApp();
  const [loading, setLoading] = useState(false);
  
  const setUser = useAuthStore((state) => state.setUser);
  const setTokens = useAuthStore((state) => state.setTokens);
  
  const handleRegister = async (values: RegisterForm) => {
    if (values.password !== values.confirmPassword) {
      message.error('Passwords do not match');
      return;
    }
    
    setLoading(true);
    
    try {
      const response = await api.post<RegisterResponse>('/api/v1/auth/register', {
        name: values.name,
        email: values.email,
        password: values.password,
      });
      
      setTokens(response.access_token, response.refresh_token);
      setUser(response.user);
      
      message.success('Registration successful');
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
          ? 'Cannot reach API. Ensure the API is running at ' +
            (process.env.NEXT_PUBLIC_API_URL ?? '') +
            ' and CORS allows this origin.'
          : msg || 'Registration failed. Please try again.';
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
          CREATE ACCOUNT
        </div>

        <Form
          name="register"
          onFinish={handleRegister}
          layout="vertical"
          requiredMark={false}
        >
          <Form.Item
            label="Full Name"
            name="name"
            rules={[
              { required: true, message: 'Name is required' },
              { min: 2, message: 'Name must be at least 2 characters' },
            ]}
          >
            <Input
              prefix={<UserOutlined style={{ color: colors.text.muted }} />}
              placeholder="Full Name"
              size="large"
              autoComplete="name"
            />
          </Form.Item>
          
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
              autoComplete="new-password"
            />
          </Form.Item>
          
          <Form.Item
            label="Confirm Password"
            name="confirmPassword"
            rules={[
              { required: true, message: 'Please confirm your password' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('password') === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error('Passwords do not match'));
                },
              }),
            ]}
          >
            <Input.Password
              prefix={<LockOutlined style={{ color: colors.text.muted }} />}
              placeholder="Confirm Password"
              size="large"
              autoComplete="new-password"
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
              Create Account
            </Button>
          </Form.Item>
        </Form>
        
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary">
            Already have an account?{' '}
            <Link href="/login" style={{ color: colors.accent.primary }}>
              Sign In
            </Link>
          </Text>
        </div>
      </C2Panel>
    </div>
  );
}
