// src/pages/SigningProfiles.tsx
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

interface SigningProfile {
    id: number;
    name: string;
    description: string;
    algorithm: string;
    validityDays: number;
}

const SigningProfileOverview: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const [profile, setProfile] = useState<SigningProfile | null>(null);

    useEffect(() => {
        fetch(`http://localhost:5293/api/admin/signing-profiles/${id}`)
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
                <li><strong>algorithm:</strong> {profile.algorithm}</li>
                <li><strong>Validity Days:</strong> {profile.validityDays}</li>
            </ul>
        </div>
    );
}

export default SigningProfileOverview;