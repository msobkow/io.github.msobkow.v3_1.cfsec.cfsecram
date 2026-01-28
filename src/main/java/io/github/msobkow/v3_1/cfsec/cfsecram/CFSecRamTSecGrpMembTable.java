
// Description: Java 25 in-memory RAM DbIO implementation for TSecGrpMemb.

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
 *	CFSecRamTSecGrpMembTable in-memory RAM DbIO implementation
 *	for TSecGrpMemb.
 */
public class CFSecRamTSecGrpMembTable
	implements ICFSecTSecGrpMembTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffTSecGrpMemb > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffTSecGrpMemb >();
	private Map< CFSecBuffTSecGrpMembByTenantIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpMemb >> dictByTenantIdx
		= new HashMap< CFSecBuffTSecGrpMembByTenantIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpMemb >>();
	private Map< CFSecBuffTSecGrpMembByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpMemb >> dictByGroupIdx
		= new HashMap< CFSecBuffTSecGrpMembByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpMemb >>();
	private Map< CFSecBuffTSecGrpMembByUserIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpMemb >> dictByUserIdx
		= new HashMap< CFSecBuffTSecGrpMembByUserIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpMemb >>();
	private Map< CFSecBuffTSecGrpMembByUUserIdxKey,
			CFSecBuffTSecGrpMemb > dictByUUserIdx
		= new HashMap< CFSecBuffTSecGrpMembByUUserIdxKey,
			CFSecBuffTSecGrpMemb >();

	public CFSecRamTSecGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffTSecGrpMemb ensureRec(ICFSecTSecGrpMemb rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecTSecGrpMemb.CLASS_CODE) {
				return( ((CFSecBuffTSecGrpMembDefaultFactory)(schema.getFactoryTSecGrpMemb())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecTSecGrpMemb createTSecGrpMemb( ICFSecAuthorization Authorization,
		ICFSecTSecGrpMemb iBuff )
	{
		final String S_ProcName = "createTSecGrpMemb";
		
		CFSecBuffTSecGrpMemb Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextTSecGrpMembIdGen();
		Buff.setRequiredTSecGrpMembId( pkey );
		CFSecBuffTSecGrpMembByTenantIdxKey keyTenantIdx = (CFSecBuffTSecGrpMembByTenantIdxKey)schema.getFactoryTSecGrpMemb().newByTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffTSecGrpMembByGroupIdxKey keyGroupIdx = (CFSecBuffTSecGrpMembByGroupIdxKey)schema.getFactoryTSecGrpMemb().newByGroupIdxKey();
		keyGroupIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpMembByUserIdxKey keyUserIdx = (CFSecBuffTSecGrpMembByUserIdxKey)schema.getFactoryTSecGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffTSecGrpMembByUUserIdxKey keyUUserIdx = (CFSecBuffTSecGrpMembByUUserIdxKey)schema.getFactoryTSecGrpMemb().newByUUserIdxKey();
		keyUUserIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyUUserIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUUserIdx.containsKey( keyUUserIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TSecGrpMembUUserIdx",
				"TSecGrpMembUUserIdx",
				keyUUserIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"Owner",
						"TSecGrpMembTenant",
						"TSecGrpMembTenant",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"TSecGrpMembGroup",
						"TSecGrpMembGroup",
						"TSecGroup",
						"TSecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		dictByUUserIdx.put( keyUUserIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecTSecGrpMemb.CLASS_CODE) {
				CFSecBuffTSecGrpMemb retbuff = ((CFSecBuffTSecGrpMemb)(schema.getFactoryTSecGrpMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecTSecGrpMemb readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerived";
		ICFSecTSecGrpMemb buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpMemb lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerived";
		ICFSecTSecGrpMemb buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamTSecGrpMemb.readAllDerived";
		ICFSecTSecGrpMemb[] retList = new ICFSecTSecGrpMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffTSecGrpMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecTSecGrpMemb[] readDerivedByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByTenantIdx";
		CFSecBuffTSecGrpMembByTenantIdxKey key = (CFSecBuffTSecGrpMembByTenantIdxKey)schema.getFactoryTSecGrpMemb().newByTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		ICFSecTSecGrpMemb[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new ICFSecTSecGrpMemb[ subdictTenantIdx.size() ];
			Iterator< CFSecBuffTSecGrpMemb > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictTenantIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new ICFSecTSecGrpMemb[0];
		}
		return( recArray );
	}

	public ICFSecTSecGrpMemb[] readDerivedByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByGroupIdx";
		CFSecBuffTSecGrpMembByGroupIdxKey key = (CFSecBuffTSecGrpMembByGroupIdxKey)schema.getFactoryTSecGrpMemb().newByGroupIdxKey();
		key.setRequiredTSecGroupId( TSecGroupId );

		ICFSecTSecGrpMemb[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new ICFSecTSecGrpMemb[ subdictGroupIdx.size() ];
			Iterator< CFSecBuffTSecGrpMemb > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictGroupIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new ICFSecTSecGrpMemb[0];
		}
		return( recArray );
	}

	public ICFSecTSecGrpMemb[] readDerivedByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByUserIdx";
		CFSecBuffTSecGrpMembByUserIdxKey key = (CFSecBuffTSecGrpMembByUserIdxKey)schema.getFactoryTSecGrpMemb().newByUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		ICFSecTSecGrpMemb[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new ICFSecTSecGrpMemb[ subdictUserIdx.size() ];
			Iterator< CFSecBuffTSecGrpMemb > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdictUserIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new ICFSecTSecGrpMemb[0];
		}
		return( recArray );
	}

	public ICFSecTSecGrpMemb readDerivedByUUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByUUserIdx";
		CFSecBuffTSecGrpMembByUUserIdxKey key = (CFSecBuffTSecGrpMembByUUserIdxKey)schema.getFactoryTSecGrpMemb().newByUUserIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTSecGroupId( TSecGroupId );
		key.setRequiredSecUserId( SecUserId );

		ICFSecTSecGrpMemb buff;
		if( dictByUUserIdx.containsKey( key ) ) {
			buff = dictByUUserIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGrpMembId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByIdIdx() ";
		ICFSecTSecGrpMemb buff;
		if( dictByPKey.containsKey( TSecGrpMembId ) ) {
			buff = dictByPKey.get( TSecGrpMembId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpMemb readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuff";
		ICFSecTSecGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecTSecGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpMemb lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecTSecGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecTSecGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpMemb[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readAllBuff";
		ICFSecTSecGrpMemb buff;
		ArrayList<ICFSecTSecGrpMemb> filteredList = new ArrayList<ICFSecTSecGrpMemb>();
		ICFSecTSecGrpMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific TSecGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific TSecGrpMemb instances in the database accessible for the Authorization.
	 */
	public ICFSecTSecGrpMemb[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecTSecGrpMemb readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGrpMembId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByIdIdx() ";
		ICFSecTSecGrpMemb buff = readDerivedByIdIdx( Authorization,
			TSecGrpMembId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTSecGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecTSecGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecTSecGrpMemb[] readBuffByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByTenantIdx() ";
		ICFSecTSecGrpMemb buff;
		ArrayList<ICFSecTSecGrpMemb> filteredList = new ArrayList<ICFSecTSecGrpMemb>();
		ICFSecTSecGrpMemb[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecTSecGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpMemb[0] ) );
	}

	public ICFSecTSecGrpMemb[] readBuffByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByGroupIdx() ";
		ICFSecTSecGrpMemb buff;
		ArrayList<ICFSecTSecGrpMemb> filteredList = new ArrayList<ICFSecTSecGrpMemb>();
		ICFSecTSecGrpMemb[] buffList = readDerivedByGroupIdx( Authorization,
			TSecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecTSecGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpMemb[0] ) );
	}

	public ICFSecTSecGrpMemb[] readBuffByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByUserIdx() ";
		ICFSecTSecGrpMemb buff;
		ArrayList<ICFSecTSecGrpMemb> filteredList = new ArrayList<ICFSecTSecGrpMemb>();
		ICFSecTSecGrpMemb[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecTSecGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpMemb[0] ) );
	}

	public ICFSecTSecGrpMemb readBuffByUUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByUUserIdx() ";
		ICFSecTSecGrpMemb buff = readDerivedByUUserIdx( Authorization,
			TenantId,
			TSecGroupId,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTSecGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecTSecGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific TSecGrpMemb buffer instances identified by the duplicate key TenantIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TenantId	The TSecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecTSecGrpMemb[] pageBuffByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByTenantIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific TSecGrpMemb buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TSecGroupId	The TSecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecTSecGrpMemb[] pageBuffByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific TSecGrpMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The TSecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecTSecGrpMemb[] pageBuffByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecTSecGrpMemb updateTSecGrpMemb( ICFSecAuthorization Authorization,
		ICFSecTSecGrpMemb iBuff )
	{
		CFSecBuffTSecGrpMemb Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffTSecGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTSecGrpMemb",
				"Existing record not found",
				"Existing record not found",
				"TSecGrpMemb",
				"TSecGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTSecGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffTSecGrpMembByTenantIdxKey existingKeyTenantIdx = (CFSecBuffTSecGrpMembByTenantIdxKey)schema.getFactoryTSecGrpMemb().newByTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffTSecGrpMembByTenantIdxKey newKeyTenantIdx = (CFSecBuffTSecGrpMembByTenantIdxKey)schema.getFactoryTSecGrpMemb().newByTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffTSecGrpMembByGroupIdxKey existingKeyGroupIdx = (CFSecBuffTSecGrpMembByGroupIdxKey)schema.getFactoryTSecGrpMemb().newByGroupIdxKey();
		existingKeyGroupIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpMembByGroupIdxKey newKeyGroupIdx = (CFSecBuffTSecGrpMembByGroupIdxKey)schema.getFactoryTSecGrpMemb().newByGroupIdxKey();
		newKeyGroupIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpMembByUserIdxKey existingKeyUserIdx = (CFSecBuffTSecGrpMembByUserIdxKey)schema.getFactoryTSecGrpMemb().newByUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffTSecGrpMembByUserIdxKey newKeyUserIdx = (CFSecBuffTSecGrpMembByUserIdxKey)schema.getFactoryTSecGrpMemb().newByUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffTSecGrpMembByUUserIdxKey existingKeyUUserIdx = (CFSecBuffTSecGrpMembByUUserIdxKey)schema.getFactoryTSecGrpMemb().newByUUserIdxKey();
		existingKeyUUserIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyUUserIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );
		existingKeyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffTSecGrpMembByUUserIdxKey newKeyUUserIdx = (CFSecBuffTSecGrpMembByUUserIdxKey)schema.getFactoryTSecGrpMemb().newByUUserIdxKey();
		newKeyUUserIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyUUserIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		newKeyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		if( ! existingKeyUUserIdx.equals( newKeyUUserIdx ) ) {
			if( dictByUUserIdx.containsKey( newKeyUUserIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTSecGrpMemb",
					"TSecGrpMembUUserIdx",
					"TSecGrpMembUUserIdx",
					newKeyUUserIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTSecGrpMemb",
						"Owner",
						"Owner",
						"TSecGrpMembTenant",
						"TSecGrpMembTenant",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTSecGrpMemb",
						"Container",
						"Container",
						"TSecGrpMembGroup",
						"TSecGrpMembGroup",
						"TSecGroup",
						"TSecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTenantIdx.get( existingKeyTenantIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTenantIdx.containsKey( newKeyTenantIdx ) ) {
			subdict = dictByTenantIdx.get( newKeyTenantIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByGroupIdx.get( existingKeyGroupIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByGroupIdx.containsKey( newKeyGroupIdx ) ) {
			subdict = dictByGroupIdx.get( newKeyGroupIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByGroupIdx.put( newKeyGroupIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByUserIdx.get( existingKeyUserIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByUserIdx.containsKey( newKeyUserIdx ) ) {
			subdict = dictByUserIdx.get( newKeyUserIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUUserIdx.remove( existingKeyUUserIdx );
		dictByUUserIdx.put( newKeyUUserIdx, Buff );

		return(Buff);
	}

	public void deleteTSecGrpMemb( ICFSecAuthorization Authorization,
		ICFSecTSecGrpMemb iBuff )
	{
		final String S_ProcName = "CFSecRamTSecGrpMembTable.deleteTSecGrpMemb() ";
		CFSecBuffTSecGrpMemb Buff = ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffTSecGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTSecGrpMemb",
				pkey );
		}
		CFSecBuffTSecGrpMembByTenantIdxKey keyTenantIdx = (CFSecBuffTSecGrpMembByTenantIdxKey)schema.getFactoryTSecGrpMemb().newByTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffTSecGrpMembByGroupIdxKey keyGroupIdx = (CFSecBuffTSecGrpMembByGroupIdxKey)schema.getFactoryTSecGrpMemb().newByGroupIdxKey();
		keyGroupIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpMembByUserIdxKey keyUserIdx = (CFSecBuffTSecGrpMembByUserIdxKey)schema.getFactoryTSecGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffTSecGrpMembByUUserIdxKey keyUUserIdx = (CFSecBuffTSecGrpMembByUUserIdxKey)schema.getFactoryTSecGrpMemb().newByUUserIdxKey();
		keyUUserIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyUUserIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

		dictByUUserIdx.remove( keyUUserIdx );

	}
	public void deleteTSecGrpMembByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffTSecGrpMemb cur;
		LinkedList<CFSecBuffTSecGrpMemb> matchSet = new LinkedList<CFSecBuffTSecGrpMemb>();
		Iterator<CFSecBuffTSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTSecGrpMemb)(schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() ));
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId )
	{
		CFSecBuffTSecGrpMembByTenantIdxKey key = (CFSecBuffTSecGrpMembByTenantIdxKey)schema.getFactoryTSecGrpMemb().newByTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteTSecGrpMembByTenantIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByTenantIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpMembByTenantIdxKey argKey )
	{
		CFSecBuffTSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTSecGrpMemb> matchSet = new LinkedList<CFSecBuffTSecGrpMemb>();
		Iterator<CFSecBuffTSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTSecGrpMemb)(schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() ));
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTSecGroupId )
	{
		CFSecBuffTSecGrpMembByGroupIdxKey key = (CFSecBuffTSecGrpMembByGroupIdxKey)schema.getFactoryTSecGrpMemb().newByGroupIdxKey();
		key.setRequiredTSecGroupId( argTSecGroupId );
		deleteTSecGrpMembByGroupIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByGroupIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpMembByGroupIdxKey argKey )
	{
		CFSecBuffTSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTSecGrpMemb> matchSet = new LinkedList<CFSecBuffTSecGrpMemb>();
		Iterator<CFSecBuffTSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTSecGrpMemb)(schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() ));
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffTSecGrpMembByUserIdxKey key = (CFSecBuffTSecGrpMembByUserIdxKey)schema.getFactoryTSecGrpMemb().newByUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteTSecGrpMembByUserIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByUserIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpMembByUserIdxKey argKey )
	{
		CFSecBuffTSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTSecGrpMemb> matchSet = new LinkedList<CFSecBuffTSecGrpMemb>();
		Iterator<CFSecBuffTSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTSecGrpMemb)(schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() ));
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByUUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId,
		CFLibDbKeyHash256 argTSecGroupId,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffTSecGrpMembByUUserIdxKey key = (CFSecBuffTSecGrpMembByUUserIdxKey)schema.getFactoryTSecGrpMemb().newByUUserIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTSecGroupId( argTSecGroupId );
		key.setRequiredSecUserId( argSecUserId );
		deleteTSecGrpMembByUUserIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByUUserIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpMembByUUserIdxKey argKey )
	{
		CFSecBuffTSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTSecGrpMemb> matchSet = new LinkedList<CFSecBuffTSecGrpMemb>();
		Iterator<CFSecBuffTSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTSecGrpMemb)(schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() ));
			deleteTSecGrpMemb( Authorization, cur );
		}
	}
}
