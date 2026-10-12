import React, { useRef, useMemo, useEffect } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Line } from '@react-three/drei'
import * as THREE from 'three'
THREE.Cache.enabled = true

const SEVERITY_COLORS = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e',
    UNKNOWN: '#6b7280',
}

const KEV_COLOR = '#22d3ee'

function Edge({ sourceNode, targetNode }) {
    // Dynamically Plot The Coordinates Creating A Physical Connection Between Two Nodes Safely
    const points = useMemo(() => {
        if (!sourceNode || !targetNode) return null
        return [
            new THREE.Vector3(sourceNode.position.x, sourceNode.position.y, sourceNode.position.z),
            new THREE.Vector3(targetNode.position.x, targetNode.position.y, targetNode.position.z)
        ]
    }, [sourceNode, targetNode])

    if (!points) return null

    return (
        <Line
            points={points}
            color="#4b5563"
            lineWidth={1}
            transparent={true}
            opacity={0.3}
        />
    )
}

// Wrap The Node In React.memo To Physically Block Wasted Graphics Processing Unit Cycles
const CVENode = React.memo(function CVENode({ cve, onSelect }) {
    const meshRef = useRef()
    const ringRef = useRef()
    const pointerDown = useRef(null)

    useFrame((state) => {
        if (meshRef.current) {
            meshRef.current.rotation.y += 0.005
        }
        if (ringRef.current) {
            const pulse = Math.sin(state.clock.elapsedTime * 3) * 0.5 + 0.5
            ringRef.current.material.emissiveIntensity = 0.5 + pulse * 1.5
        }
    })

    useEffect(() => {
        // Guarantee The Cursor Resets To Default If The Node Unmounts While Hovered
        return () => {
            document.body.style.cursor = 'default'
        }
    }, [])

    const color = SEVERITY_COLORS[cve.severity] || SEVERITY_COLORS.UNKNOWN
    const size = cve.score ? Math.max(0.8, cve.score / 6) : 0.8

    return (
        <group position={[cve.position.x, cve.position.y, cve.position.z]}>
            <mesh
                ref={meshRef}
                onPointerDown={(e) => {
                    pointerDown.current = { x: e.clientX, y: e.clientY }
                }}
                onPointerUp={(e) => {
                    if (pointerDown.current) {
                        const dx = Math.abs(e.clientX - pointerDown.current.x)
                        const dy = Math.abs(e.clientY - pointerDown.current.y)
                        if (dx < 5 && dy < 5) {
                            e.stopPropagation()
                            onSelect(cve)
                        }
                    }
                }}
                onPointerOver={() => document.body.style.cursor = 'pointer'}
                onPointerOut={() => document.body.style.cursor = 'default'}
            >
                <sphereGeometry args={[size, 16, 16]} />
                <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.4} />
            </mesh>

            {cve.is_kev && (
                <mesh ref={ringRef} rotation={[Math.PI / 2, 0, 0]}>
                    <torusGeometry args={[size * 1.6, 0.1, 8, 32]} />
                    <meshStandardMaterial
                        color={KEV_COLOR}
                        emissive={KEV_COLOR}
                        emissiveIntensity={1}
                    />
                </mesh>
            )}
        </group>
    )
}, (prevProps, nextProps) => {
    return prevProps.cve === nextProps.cve &&
        prevProps.onSelect === nextProps.onSelect
})

export default function ThreatGlobe({ cves, onSelect }) {
    // Gracefully Defend Against Prop Changes By Safely Unpacking The Dictionary Using Optional Chaining
    const nodes = cves?.nodes || (Array.isArray(cves) ? cves : [])
    const edges = cves?.edges || []

    // Create A Hash Map For Rapid Positional Lookup When Drawing Edges
    const nodeMap = useMemo(() => {
        const map = {}
        nodes.forEach(node => {
            map[node.id] = node
        })
        return map
    }, [nodes])

    return (
        <Canvas camera={{ position: [0, 0, 200], fov: 60 }}>
            <ambientLight intensity={0.4} />
            <pointLight position={[100, 100, 100]} intensity={1} />
            <OrbitControls enableZoom={true} enablePan={true} autoRotate={true} autoRotateSpeed={0.3} />

            {/* Render Edges First So They Lie Visually Beneath The Spheres */}
            {edges.map((edge, index) => {
                const sourceNode = nodeMap[edge.source]
                const targetNode = nodeMap[edge.target]

                if (sourceNode && targetNode) {
                    return <Edge key={index} sourceNode={sourceNode} targetNode={targetNode} />
                }
                return null
            })}

            {/* Render The Spherical Threat Nodes */}
            {nodes.map((cve) => (
                <CVENode key={cve.id} cve={cve} onSelect={onSelect} />
            ))}
        </Canvas>
    )
}