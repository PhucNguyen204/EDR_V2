import React from 'react';
import { Alert, Button } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Alert
          message="Something went wrong"
          description={
            <div>
              <p>An error occurred while rendering this component.</p>
              <details style={{ marginTop: 10 }}>
                <summary>Error details</summary>
                <pre style={{ fontSize: '12px', marginTop: 5 }}>
                  {this.state.error?.toString()}
                </pre>
              </details>
            </div>
          }
          type="error"
          showIcon
          action={
            <Button 
              size="small" 
              icon={<ReloadOutlined />}
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.reload();
              }}
            >
              Reload
            </Button>
          }
        />
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
