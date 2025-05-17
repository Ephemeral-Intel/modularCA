import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const navItems = [
    { name: 'Dashboard', path: '/' },
    { name: 'CA', path: '/ca' },
    { name: 'RA', path: '/ra' },
    { name: 'Users', path: '/users' },
    { name: 'Settings', path: '/settings' }
];

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const location = useLocation();

    return (
        <div className="flex min-h-screen">
            <nav className="w-64 bg-gray-900 text-white p-4">
                <h2 className="text-2xl font-bold mb-6">ModularCA</h2>
                <ul className="space-y-2">
                    {navItems.map((item) => (
                        <li key={item.path}>
                            <Link
                                to={item.path}
                                className={`block px-3 py-2 rounded-md hover:bg-gray-700 ${location.pathname === item.path ? 'bg-gray-700' : ''
                                    }`}
                            >
                                {item.name}
                            </Link>
                        </li>
                    ))}
                </ul>
            </nav>
            <main className="flex-1 p-6 bg-gray-50">{children}</main>
        </div>
    );
};

export default Layout;
