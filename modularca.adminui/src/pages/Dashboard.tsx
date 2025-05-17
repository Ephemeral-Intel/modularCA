import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

interface CertProfile {
    id: number;
    name: string;
    description: string;
    validityPeriod: string;
}

interface SignProfile {
    id: number;
    name: string;
    description: string;
    validityPeriod: string;
}
interface CaCert {
    certificateId: string;
    subjectDN: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
}

const Dashboard: React.FC = () => {
    const [profiles, setProfiles] = useState<CertProfile[]>([]);
    const [certProfileError, setCertProfileError] = useState<string | null>(null);
    const [signProfileError, setSignProfileError] = useState<string | null>(null);
    const [caCertError, setCaCertError] = useState<string | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<SignProfile[]>([]);
    const [CaCerts, setCaCerts] = useState<CaCert[]>([]);

    useEffect(() => {
        fetch('http://localhost:5293/api/admin/cert-profiles')
            .then((res) => {
                if (!res.ok) throw new Error('Failed to fetch certificate profiles');
                return res.json();
            })
            .then(setProfiles)
            .catch((certProfileError) => setCertProfileError(certProfileError.message));
    }, []);

    useEffect(() => {
        fetch('http://localhost:5293/api/admin/signing-profiles')
            .then((res) => {
                if (!res.ok) throw new Error('Failed to fetch signing profiles');
                return res.json();
            })
            .then(setSigningProfiles)
            .catch((signProfileError) => setSignProfileError(signProfileError.message));
    }, []);

    useEffect(() => {
        fetch('http://localhost:5293/api/admin/ca/all')
            .then((res) => {
                if (!res.ok) throw new Error('Failed to fetch certificate authorities');
                return res.json();
            })
            .then(setCaCerts)
            .catch((caCertError) => setCaCertError(caCertError.message));
    }, []);

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">ModularCA Admin Dashboard</h1>

            <div className="flex gap-6">
                {/* Cert Profiles card — 1/4 width */}
                <div className="w-1/4 min-w-[250px] max-w-[25%] bg-white rounded-xl shadow border border-gray-200 p-4">
                    <h2 className="text-lg font-semibold text-gray-800 mb-4">Certificate Request Profiles</h2>
                    {certProfileError && <p className="text-red-600">{certProfileError}</p>}
                    {profiles.length === 0 ? (
                        <p className="text-sm text-gray-500 italic">No certificate request profiles found.</p>
                    ) : (
                        <ul className="divide-y divide-gray-200">
                            {profiles.map((certProfile) => (
                                <li key={certProfile.id} className="py-3">
                                    <Link
                                        to={`/cert-profile/overview/${certProfile.id}`}
                                        className="text-blue-600 font-medium text-base hover:underline"
                                    >
                                        {certProfile.name}
                                    </Link>
                                    <p className="text-sm text-gray-600">{certProfile.description}</p>
                                    <p className="text-sm text-gray-400 mt-1">
                                        Validity: {certProfile.validityPeriod}
                                    </p>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
                <div className="w-1/4 min-w-[250px] max-w-[25%] bg-white rounded-xl shadow border border-gray-200 p-4">
                    <h2 className="text-lg font-semibold text-gray-800 mb-4">CA Certificates</h2>
                    {signProfileError && <p className="text-red-600">{signProfileError}</p>}
                    {signingProfiles.length === 0 ? (
                        <p className="text-sm text-gray-500 italic">No certificate profiles found.</p>
                    ) : (
                        <ul className="divide-y divide-gray-200">
                                {signingProfiles.map((signProfile) => (
                                    <li key={signProfile.id} className="py-3">
                                    <Link
                                            to={`/signing-profile/overview/${signProfile.id}`}
                                        className="text-blue-600 font-medium text-base hover:underline"
                                    >
                                            {signProfile.name}
                                    </Link>
                                        <p className="text-sm text-gray-600">{signProfile.description}</p>
                                    <p className="text-sm text-gray-400 mt-1">
                                            Validity: {signProfile.validityPeriod}
                                    </p>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
                <div className="w-1/4 min-w-[250px] max-w-[25%] bg-white rounded-xl shadow border border-gray-200 p-4">
                    <h2 className="text-lg font-semibold text-gray-800 mb-4">Certificate Signing Profiles</h2>
                    {caCertError && <p className="text-red-600">{caCertError}</p>}
                    {CaCerts.length === 0 ? (
                        <p className="text-sm text-gray-500 italic">No CA certificates found.</p>
                    ) : (
                            <ul className="divide-y divide-gray-200">
                                {CaCerts.map((CaCert) => (
                                    <li key={CaCert.certificateId} className="py-3">
                                    <Link
                                            to={`/signing-profile/overview/${CaCert.certificateId}`}
                                        className="text-blue-600 font-medium text-base hover:underline"
                                    >
                                            {CaCert.subjectDN}
                                    </Link>
                                    <p className="text-sm text-gray-400 mt-1">
                                            issuer: {CaCert.issuer}
                                            notBefore: {CaCert.notBefore}
                                    </p>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </div>
        </div>

    );
};

export default Dashboard;
