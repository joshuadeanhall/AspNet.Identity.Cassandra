using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNet.Identity.Cassandra.Entities;
using Cassandra;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Store
{
    public class CassandraUserStore<TUser> : IUserStore<TUser>,
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IQueryableUserStore<TUser>,
        IUserTwoFactorStore<TUser, string>,
        IUserLockoutStore<TUser, string>,
        IUserEmailStore<TUser>,
        IUserPhoneNumberStore<TUser> where TUser : CassandraUser
    {

        private Session _session;

        public CassandraUserStore(Session session)
        {
            _session = session;
        }

        public async Task CreateAsync(TUser user)
        {
            var prepared =_session.Prepare("INSERT into users (username, passwordhash, securitystamp) VALUES (?, ?, ?)");
            var bound = prepared.Bind(user.UserName, user.PasswordHash, user.SecurityStamp);
            await Task<RowSet>.Factory.FromAsync(_session.BeginExecute, _session.EndExecute, bound, null);
        }

        public async Task UpdateAsync(TUser user)
        {
            var prepared = _session.Prepare("UPDATE users SET passwordhash = ?, securitystamp = ? WHERE username = ?");
            var bound = prepared.Bind(user.PasswordHash, user.SecurityStamp, user.UserName);
            _session.Execute(bound);
            await ExecuteBountStatementAsync(bound);
        }

        private async Task ExecuteBountStatementAsync(BoundStatement bound)
        {
            await Task<RowSet>.Factory.FromAsync(_session.BeginExecute, _session.EndExecute, bound, null);
        }

        public async Task DeleteAsync(TUser user)
        {
            var prepared = _session.Prepare("DELETE from users where username = ?");
            var bound = prepared.Bind(user.UserName);
            await ExecuteBountStatementAsync(bound);
        }

        public Task<TUser> FindByIdAsync(string userId)
        {
            throw new NotImplementedException();
        }

        public Task<TUser> FindByNameAsync(string userName)
        {
            throw new NotImplementedException();
        }

        public Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            throw new NotImplementedException();
        }

        public Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            throw new NotImplementedException();
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<TUser> FindAsync(UserLoginInfo login)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task AddClaimAsync(TUser user, Claim claim)
        {
            throw new NotImplementedException();
        }

        public Task RemoveClaimAsync(TUser user, Claim claim)
        {
            throw new NotImplementedException();
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            user.SetPasswordHash(passwordHash);
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            user.SetSecurityStamp(stamp);
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public IQueryable<TUser> Users { get; private set; }
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            throw new NotImplementedException();
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task ResetAccessFailedCountAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
        }

        public Task<TUser> FindByEmailAsync(string email)
        {
            throw new NotImplementedException();
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
        }


        protected void Dispose(bool disposing)
        {
            _session.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
