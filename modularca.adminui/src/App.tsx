import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import CertProfileOverview from './pages/CertProfileOverview';
import Layout from './components/Layout';
import SigningProfileOverview from './pages/SigningProfileOverview';

const App: React.FC = () => {
    return (
        <Router>
            <Layout>
                <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/cert-profile/overview/:id" element={<CertProfileOverview />} />
                    {/* Future stubs */}
                    <Route path="/ca" element={<div>CA Page</div>} />
                    <Route path="/ra" element={<div>RA Page</div>} />
                    <Route path="/users" element={<div>Users Page</div>} />
                    <Route path="/settings" element={<div>Settings Page</div>} />
                    <Route path="/signing-profile/overview/:id" element={<SigningProfileOverview />} />

                </Routes>
            </Layout>
        </Router>
    );
};

export default App;
