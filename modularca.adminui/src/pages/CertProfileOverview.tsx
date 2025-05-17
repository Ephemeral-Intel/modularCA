import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

interface CertProfile {
    id: number;
    name: string;
    description: string;
    includeRootInChain: boolean;
    keyUsage: string;
    extendedKeyUsage: string;
    validityPeriod: string;
}

const CertProfileOverview: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const [profile, setProfile] = useState<CertProfile | null>(null);

    useEffect(() => {
        fetch(`http://localhost:5293/api/admin/cert-profiles/${id}`)
            .then(res => res.json())
            .then(setProfile)
            .catch(err => console.error(err));
    }, [id]);

    if (!profile) return <div>Loading profile...</div>;

    return (
        <div>
            <h1 className="text-2xl font-bold mb-2">{profile.name}</h1>
            <p className="text-gray-600 italic mb-4">{profile.description}</p>
            <ul className="text-sm space-y-1">
                <li><strong>Include Root:</strong> {profile.includeRootInChain ? 'Yes' : 'No'}</li>
                <li><strong>Key Usage:</strong> {profile.keyUsage}</li>
                <li><strong>Extended Key Usage:</strong> {profile.extendedKeyUsage}</li>
                <li><strong>Validity:</strong> {profile.validityPeriod}</li>
            </ul>
        </div>
    );
};

export default CertProfileOverview;
