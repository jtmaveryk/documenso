import type { User } from '@documenso/prisma/client';

import { ENCRYPTION_KEY } from '../../constants/crypto';

type IsTwoFactorAuthenticationEnabledOptions = {
  user: User;
};

export const isTwoFactorAuthenticationEnabled = ({
  user,
}: IsTwoFactorAuthenticationEnabledOptions) => {
  return user.twoFactorEnabled && typeof ENCRYPTION_KEY === 'string';
};
