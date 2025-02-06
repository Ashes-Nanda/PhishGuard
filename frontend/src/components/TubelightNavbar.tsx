import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Link as RouterLink } from 'react-router-dom';
import { Icon, Box, HStack } from '@chakra-ui/react';
import { FaHome, FaHistory, FaInfoCircle, FaShieldAlt } from 'react-icons/fa';

interface NavItem {
	name: string;
	url: string;
	icon: any;
}

interface NavBarProps {
	items?: NavItem[];
}

const defaultItems = [
	{ name: 'Home', url: '/', icon: FaHome },
	{ name: 'History', url: '/history', icon: FaHistory },
	{ name: 'About', url: '/about', icon: FaInfoCircle },
	{ name: 'Security Guide', url: '/security-guide', icon: FaShieldAlt }
];

export function TubelightNavbar({ items = defaultItems }: NavBarProps) {
	const [activeTab, setActiveTab] = useState(items[0].name);
	const [isVisible, setIsVisible] = useState(true);
	const [lastScrollY, setLastScrollY] = useState(0);

	useEffect(() => {
		const handleScroll = () => {
			const currentScrollY = window.scrollY;
			if (currentScrollY < lastScrollY || currentScrollY < 100) {
				setIsVisible(true);
			} else {
				setIsVisible(false);
			}
			setLastScrollY(currentScrollY);
		};

		window.addEventListener("scroll", handleScroll);
		return () => window.removeEventListener("scroll", handleScroll);
	}, [lastScrollY]);

	return (
		<AnimatePresence mode="wait">
			{isVisible && (
				<motion.div
					initial={{ y: -100, opacity: 0 }}
					animate={{ y: 0, opacity: 1 }}
					exit={{ y: -100, opacity: 0 }}
					transition={{ duration: 0.3 }}
					style={{
						position: 'fixed',
						top: 0,
						left: 0,
						right: 0,
						height: '4rem',
						zIndex: 100,
						backdropFilter: 'blur(8px)',
						background: 'rgba(0, 0, 0, 0.3)',
						display: 'flex',
						alignItems: 'center',
						justifyContent: 'center',
					}}
				>
					<Box
						maxW="1200px"
						w="100%"
						mx="auto"
						px={{ base: 4, md: 6 }}
						display="flex"
						justifyContent="center"
					>
						<HStack
							spacing={{ base: 3, md: 4 }}
							bg="glassDark"
							borderWidth="1px"
							borderColor="glassStroke"
							backdropFilter="blur(10px)"
							py={{ base: 2, md: 2.5 }}
							px={{ base: 4, md: 6 }}
							borderRadius="full"
							boxShadow="lg"
							justify="center"
							align="center"
						>
							{items.map((item) => (
								<RouterLink
									key={item.name}
									to={item.url}
									onClick={() => setActiveTab(item.name)}
									style={{
										position: 'relative',
										cursor: 'pointer',
										padding: '0.625rem 1.25rem',
										borderRadius: '9999px',
										fontSize: '0.875rem',
										fontWeight: '600',
										color: activeTab === item.name ? 'var(--chakra-colors-primary-400)' : 'var(--chakra-colors-whiteAlpha-800)',
										transition: 'all 0.2s',
										display: 'flex',
										alignItems: 'center',
										justifyContent: 'center',
										minWidth: '80px',
										whiteSpace: 'nowrap',
									}}
								>
									<Box display={{ base: 'none', md: 'block' }}>{item.name}</Box>
									<Box display={{ base: 'block', md: 'none' }}>
										<Icon as={item.icon} boxSize={5.5} />
									</Box>
									{activeTab === item.name && (
										<motion.div
											layoutId="lamp"
											style={{
												position: 'absolute',
												inset: 0,
												width: '100%',
												backgroundColor: 'rgba(0, 255, 169, 0.05)',
												borderRadius: '9999px',
												zIndex: -1,
											}}
											initial={false}
											transition={{
												type: "spring",
												stiffness: 300,
												damping: 30,
											}}
										>
											<div
												style={{
													position: 'absolute',
													top: '-1.25rem',
													left: '50%',
													transform: 'translateX(-50%)',
													width: '2.75rem',
													height: '0.25rem',
													backgroundColor: 'var(--chakra-colors-primary-400)',
													borderTopLeftRadius: '9999px',
													borderTopRightRadius: '9999px',
												}}
											>
												<div
													style={{
														position: 'absolute',
														width: '4.5rem',
														height: '2.25rem',
														backgroundColor: 'rgba(0, 255, 169, 0.15)',
														borderRadius: '9999px',
														filter: 'blur(14px)',
														top: '-1.25rem',
														left: '-0.875rem',
													}}
												/>
												<div
													style={{
														position: 'absolute',
														width: '3.5rem',
														height: '1.75rem',
														backgroundColor: 'rgba(0, 255, 169, 0.15)',
														borderRadius: '9999px',
														filter: 'blur(10px)',
														top: '-1rem',
														left: '-0.375rem',
													}}
												/>
												<div
													style={{
														position: 'absolute',
														width: '2rem',
														height: '1.25rem',
														backgroundColor: 'rgba(0, 255, 169, 0.2)',
														borderRadius: '9999px',
														filter: 'blur(6px)',
														top: '-0.75rem',
														left: '0.375rem',
													}}
												/>
											</div>
										</motion.div>
									)}
								</RouterLink>
							))}
						</HStack>
					</Box>
				</motion.div>
			)}
		</AnimatePresence>
	);
}


