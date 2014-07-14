using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests for claims storage.
    /// </summary>
    [TestFixture]
    public class ClaimsTests : IntegrationTestBase
    {
        [Test]
        public async void AddRemoveClaims()
        {
            // Create a user
            var user = new CassandraUser(Guid.NewGuid()) {UserName = "claimsUser1"};
            await UserManager.CreateAsync(user);

            // User should not have any claims initially
            IList<Claim> claims = await UserManager.GetClaimsAsync(user.Id);
            claims.Should().BeEmpty();

            // Should be able to add claims to user and retrieve them
            var claimsToAdd = new[]
            {
                new Claim("hometown", "Cincinnati, OH"),
                new Claim("dob", "4/16/1983")
            };

            IdentityResult result;
            foreach (Claim claim in claimsToAdd)
            {
                result = await UserManager.AddClaimAsync(user.Id, claim);
                result.ShouldBeSuccess();
            }

            claims = await UserManager.GetClaimsAsync(user.Id);
            claims.Should().NotBeEmpty()
                  .And.HaveCount(claimsToAdd.Length);
            claims.ShouldAllBeEquivalentTo(claimsToAdd);
            
            // Should be able to remove a claim and get the correct claims back
            result = await UserManager.RemoveClaimAsync(user.Id, claimsToAdd[0]);
            result.ShouldBeSuccess();

            claims = await UserManager.GetClaimsAsync(user.Id);
            claims.Should().NotBeEmpty()
                .And.HaveCount(claimsToAdd.Length - 1);
            claims.ShouldAllBeEquivalentTo(claimsToAdd.Where((_, idx) => idx != 0));
        }
    }
}
