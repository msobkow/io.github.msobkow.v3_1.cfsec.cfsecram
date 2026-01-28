
// Description: Java 25 in-memory RAM DbIO implementation for Tenant.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamTenantTable in-memory RAM DbIO implementation
 *	for Tenant.
 */
public class CFSecRamTenantTable
	implements ICFSecTenantTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffTenant > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffTenant >();
	private Map< CFSecBuffTenantByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTenant >> dictByClusterIdx
		= new HashMap< CFSecBuffTenantByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTenant >>();
	private Map< CFSecBuffTenantByUNameIdxKey,
			CFSecBuffTenant > dictByUNameIdx
		= new HashMap< CFSecBuffTenantByUNameIdxKey,
			CFSecBuffTenant >();

	public CFSecRamTenantTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffTenant ensureRec(ICFSecTenant rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecTenant.CLASS_CODE) {
				return( ((CFSecBuffTenantDefaultFactory)(schema.getFactoryTenant())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecTenant createTenant( ICFSecAuthorization Authorization,
		ICFSecTenant iBuff )
	{
		final String S_ProcName = "createTenant";
		
		CFSecBuffTenant Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextTenantIdGen();
		Buff.setRequiredId( pkey );
		CFSecBuffTenantByClusterIdxKey keyClusterIdx = (CFSecBuffTenantByClusterIdxKey)schema.getFactoryTenant().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffTenantByUNameIdxKey keyUNameIdx = (CFSecBuffTenantByUNameIdxKey)schema.getFactoryTenant().newByUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUNameIdx.setRequiredTenantName( Buff.getRequiredTenantName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TenantUNameIdx",
				"TenantUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"TenantCluster",
						"TenantCluster",
						"Cluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTenant > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTenant >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecTenant.CLASS_CODE) {
				CFSecBuffTenant retbuff = ((CFSecBuffTenant)(schema.getFactoryTenant().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecTenant readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTenant.readDerived";
		ICFSecTenant buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTenant lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTenant.readDerived";
		ICFSecTenant buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTenant[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamTenant.readAllDerived";
		ICFSecTenant[] retList = new ICFSecTenant[ dictByPKey.values().size() ];
		Iterator< CFSecBuffTenant > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecTenant[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamTenant.readDerivedByClusterIdx";
		CFSecBuffTenantByClusterIdxKey key = (CFSecBuffTenantByClusterIdxKey)schema.getFactoryTenant().newByClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		ICFSecTenant[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTenant > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecTenant[ subdictClusterIdx.size() ];
			Iterator< CFSecBuffTenant > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTenant > subdictClusterIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTenant >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecTenant[0];
		}
		return( recArray );
	}

	public ICFSecTenant readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String TenantName )
	{
		final String S_ProcName = "CFSecRamTenant.readDerivedByUNameIdx";
		CFSecBuffTenantByUNameIdxKey key = (CFSecBuffTenantByUNameIdxKey)schema.getFactoryTenant().newByUNameIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredTenantName( TenantName );

		ICFSecTenant buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTenant readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 Id )
	{
		final String S_ProcName = "CFSecRamTenant.readDerivedByIdIdx() ";
		ICFSecTenant buff;
		if( dictByPKey.containsKey( Id ) ) {
			buff = dictByPKey.get( Id );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTenant readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTenant.readRec";
		ICFSecTenant buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecTenant.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTenant lockRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecTenant buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecTenant.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTenant[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamTenant.readAllRec";
		ICFSecTenant buff;
		ArrayList<ICFSecTenant> filteredList = new ArrayList<ICFSecTenant>();
		ICFSecTenant[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTenant.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecTenant[0] ) );
	}

	/**
	 *	Read a page of all the specific Tenant buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific Tenant instances in the database accessible for the Authorization.
	 */
	public ICFSecTenant[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecTenant readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 Id )
	{
		final String S_ProcName = "CFSecRamTenant.readRecByIdIdx() ";
		ICFSecTenant buff = readDerivedByIdIdx( Authorization,
			Id );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTenant.CLASS_CODE ) ) {
			return( (ICFSecTenant)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecTenant[] readRecByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamTenant.readRecByClusterIdx() ";
		ICFSecTenant buff;
		ArrayList<ICFSecTenant> filteredList = new ArrayList<ICFSecTenant>();
		ICFSecTenant[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTenant.CLASS_CODE ) ) {
				filteredList.add( (ICFSecTenant)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTenant[0] ) );
	}

	public ICFSecTenant readRecByUNameIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String TenantName )
	{
		final String S_ProcName = "CFSecRamTenant.readRecByUNameIdx() ";
		ICFSecTenant buff = readDerivedByUNameIdx( Authorization,
			ClusterId,
			TenantName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTenant.CLASS_CODE ) ) {
			return( (ICFSecTenant)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific Tenant buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The Tenant key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecTenant[] pageRecByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 priorId )
	{
		final String S_ProcName = "pageRecByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecTenant updateTenant( ICFSecAuthorization Authorization,
		ICFSecTenant iBuff )
	{
		CFSecBuffTenant Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffTenant existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTenant",
				"Existing record not found",
				"Existing record not found",
				"Tenant",
				"Tenant",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTenant",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffTenantByClusterIdxKey existingKeyClusterIdx = (CFSecBuffTenantByClusterIdxKey)schema.getFactoryTenant().newByClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffTenantByClusterIdxKey newKeyClusterIdx = (CFSecBuffTenantByClusterIdxKey)schema.getFactoryTenant().newByClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffTenantByUNameIdxKey existingKeyUNameIdx = (CFSecBuffTenantByUNameIdxKey)schema.getFactoryTenant().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUNameIdx.setRequiredTenantName( existing.getRequiredTenantName() );

		CFSecBuffTenantByUNameIdxKey newKeyUNameIdx = (CFSecBuffTenantByUNameIdxKey)schema.getFactoryTenant().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUNameIdx.setRequiredTenantName( Buff.getRequiredTenantName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTenant",
					"TenantUNameIdx",
					"TenantUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTenant",
						"Container",
						"Container",
						"TenantCluster",
						"TenantCluster",
						"Cluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffTenant > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTenant >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		return(Buff);
	}

	public void deleteTenant( ICFSecAuthorization Authorization,
		ICFSecTenant iBuff )
	{
		final String S_ProcName = "CFSecRamTenantTable.deleteTenant() ";
		CFSecBuffTenant Buff = ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffTenant existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTenant",
				pkey );
		}
		CFSecBuffTSecGroup buffDelIncludedByGroup;
		ICFSecTSecGroup arrDelIncludedByGroup[] = schema.getTableTSecGroup().readDerivedByTenantIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelIncludedByGroup = 0; idxDelIncludedByGroup < arrDelIncludedByGroup.length; idxDelIncludedByGroup++ ) {
			buffDelIncludedByGroup = (CFSecBuffTSecGroup)(arrDelIncludedByGroup[idxDelIncludedByGroup]);
					schema.getTableTSecGrpInc().deleteTSecGrpIncByIncludeIdx( Authorization,
						buffDelIncludedByGroup.getRequiredTSecGroupId() );
		}
		CFSecBuffTSecGroup buffDelGrpMembs;
		ICFSecTSecGroup arrDelGrpMembs[] = schema.getTableTSecGroup().readDerivedByTenantIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelGrpMembs = 0; idxDelGrpMembs < arrDelGrpMembs.length; idxDelGrpMembs++ ) {
			buffDelGrpMembs = (CFSecBuffTSecGroup)(arrDelGrpMembs[idxDelGrpMembs]);
					schema.getTableTSecGrpMemb().deleteTSecGrpMembByGroupIdx( Authorization,
						buffDelGrpMembs.getRequiredTSecGroupId() );
		}
		CFSecBuffTSecGroup buffDelGrpIncs;
		ICFSecTSecGroup arrDelGrpIncs[] = schema.getTableTSecGroup().readDerivedByTenantIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelGrpIncs = 0; idxDelGrpIncs < arrDelGrpIncs.length; idxDelGrpIncs++ ) {
			buffDelGrpIncs = (CFSecBuffTSecGroup)(arrDelGrpIncs[idxDelGrpIncs]);
					schema.getTableTSecGrpInc().deleteTSecGrpIncByGroupIdx( Authorization,
						buffDelGrpIncs.getRequiredTSecGroupId() );
		}
					schema.getTableTSecGroup().deleteTSecGroupByTenantIdx( Authorization,
						existing.getRequiredId() );
		CFSecBuffTenantByClusterIdxKey keyClusterIdx = (CFSecBuffTenantByClusterIdxKey)schema.getFactoryTenant().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffTenantByUNameIdxKey keyUNameIdx = (CFSecBuffTenantByUNameIdxKey)schema.getFactoryTenant().newByUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUNameIdx.setRequiredTenantName( existing.getRequiredTenantName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffTenant > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	public void deleteTenantByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffTenant cur;
		LinkedList<CFSecBuffTenant> matchSet = new LinkedList<CFSecBuffTenant>();
		Iterator<CFSecBuffTenant> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTenant> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTenant)(schema.getTableTenant().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() ));
			deleteTenant( Authorization, cur );
		}
	}

	public void deleteTenantByClusterIdx( ICFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecBuffTenantByClusterIdxKey key = (CFSecBuffTenantByClusterIdxKey)schema.getFactoryTenant().newByClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteTenantByClusterIdx( Authorization, key );
	}

	public void deleteTenantByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecTenantByClusterIdxKey argKey )
	{
		CFSecBuffTenant cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTenant> matchSet = new LinkedList<CFSecBuffTenant>();
		Iterator<CFSecBuffTenant> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTenant> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTenant)(schema.getTableTenant().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() ));
			deleteTenant( Authorization, cur );
		}
	}

	public void deleteTenantByUNameIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		String argTenantName )
	{
		CFSecBuffTenantByUNameIdxKey key = (CFSecBuffTenantByUNameIdxKey)schema.getFactoryTenant().newByUNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredTenantName( argTenantName );
		deleteTenantByUNameIdx( Authorization, key );
	}

	public void deleteTenantByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecTenantByUNameIdxKey argKey )
	{
		CFSecBuffTenant cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTenant> matchSet = new LinkedList<CFSecBuffTenant>();
		Iterator<CFSecBuffTenant> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTenant> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTenant)(schema.getTableTenant().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() ));
			deleteTenant( Authorization, cur );
		}
	}
}
