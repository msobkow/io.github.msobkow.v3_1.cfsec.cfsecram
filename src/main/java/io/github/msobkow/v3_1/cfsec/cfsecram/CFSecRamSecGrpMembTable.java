
// Description: Java 25 in-memory RAM DbIO implementation for SecGrpMemb.

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
 *	CFSecRamSecGrpMembTable in-memory RAM DbIO implementation
 *	for SecGrpMemb.
 */
public class CFSecRamSecGrpMembTable
	implements ICFSecSecGrpMembTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecGrpMemb > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecGrpMemb >();
	private Map< CFSecBuffSecGrpMembByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpMemb >> dictByClusterIdx
		= new HashMap< CFSecBuffSecGrpMembByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpMemb >>();
	private Map< CFSecBuffSecGrpMembByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpMemb >> dictByGroupIdx
		= new HashMap< CFSecBuffSecGrpMembByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpMemb >>();
	private Map< CFSecBuffSecGrpMembByUserIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpMemb >> dictByUserIdx
		= new HashMap< CFSecBuffSecGrpMembByUserIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpMemb >>();
	private Map< CFSecBuffSecGrpMembByUUserIdxKey,
			CFSecBuffSecGrpMemb > dictByUUserIdx
		= new HashMap< CFSecBuffSecGrpMembByUUserIdxKey,
			CFSecBuffSecGrpMemb >();

	public CFSecRamSecGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecGrpMemb ensureRec(ICFSecSecGrpMemb rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecGrpMemb.CLASS_CODE) {
				return( ((CFSecBuffSecGrpMembDefaultFactory)(schema.getFactorySecGrpMemb())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecSecGrpMemb createSecGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecGrpMemb iBuff )
	{
		final String S_ProcName = "createSecGrpMemb";
		
		CFSecBuffSecGrpMemb Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextSecGrpMembIdGen();
		Buff.setRequiredSecGrpMembId( pkey );
		CFSecBuffSecGrpMembByClusterIdxKey keyClusterIdx = (CFSecBuffSecGrpMembByClusterIdxKey)schema.getFactorySecGrpMemb().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecGrpMembByGroupIdxKey keyGroupIdx = (CFSecBuffSecGrpMembByGroupIdxKey)schema.getFactorySecGrpMemb().newByGroupIdxKey();
		keyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecBuffSecGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecGrpMembByUserIdxKey)schema.getFactorySecGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecGrpMembByUUserIdxKey keyUUserIdx = (CFSecBuffSecGrpMembByUUserIdxKey)schema.getFactorySecGrpMemb().newByUUserIdxKey();
		keyUUserIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUUserIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUUserIdx.containsKey( keyUUserIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecGrpMembUUserIdx",
				"SecGrpMembUUserIdx",
				keyUUserIdx );
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
						"Owner",
						"Owner",
						"SecGrpMembCluster",
						"SecGrpMembCluster",
						"Cluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecGrpMembGroup",
						"SecGrpMembGroup",
						"SecGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		dictByUUserIdx.put( keyUUserIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecGrpMemb.CLASS_CODE) {
				CFSecBuffSecGrpMemb retbuff = ((CFSecBuffSecGrpMemb)(schema.getFactorySecGrpMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecSecGrpMemb readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerived";
		ICFSecSecGrpMemb buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpMemb lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerived";
		ICFSecSecGrpMemb buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecGrpMemb.readAllDerived";
		ICFSecSecGrpMemb[] retList = new ICFSecSecGrpMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecGrpMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecSecGrpMemb[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByClusterIdx";
		CFSecBuffSecGrpMembByClusterIdxKey key = (CFSecBuffSecGrpMembByClusterIdxKey)schema.getFactorySecGrpMemb().newByClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		ICFSecSecGrpMemb[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecSecGrpMemb[ subdictClusterIdx.size() ];
			Iterator< CFSecBuffSecGrpMemb > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictClusterIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecSecGrpMemb[0];
		}
		return( recArray );
	}

	public ICFSecSecGrpMemb[] readDerivedByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByGroupIdx";
		CFSecBuffSecGrpMembByGroupIdxKey key = (CFSecBuffSecGrpMembByGroupIdxKey)schema.getFactorySecGrpMemb().newByGroupIdxKey();
		key.setRequiredSecGroupId( SecGroupId );

		ICFSecSecGrpMemb[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new ICFSecSecGrpMemb[ subdictGroupIdx.size() ];
			Iterator< CFSecBuffSecGrpMemb > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictGroupIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new ICFSecSecGrpMemb[0];
		}
		return( recArray );
	}

	public ICFSecSecGrpMemb[] readDerivedByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByUserIdx";
		CFSecBuffSecGrpMembByUserIdxKey key = (CFSecBuffSecGrpMembByUserIdxKey)schema.getFactorySecGrpMemb().newByUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		ICFSecSecGrpMemb[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new ICFSecSecGrpMemb[ subdictUserIdx.size() ];
			Iterator< CFSecBuffSecGrpMemb > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdictUserIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new ICFSecSecGrpMemb[0];
		}
		return( recArray );
	}

	public ICFSecSecGrpMemb readDerivedByUUserIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByUUserIdx";
		CFSecBuffSecGrpMembByUUserIdxKey key = (CFSecBuffSecGrpMembByUUserIdxKey)schema.getFactorySecGrpMemb().newByUUserIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );
		key.setRequiredSecUserId( SecUserId );

		ICFSecSecGrpMemb buff;
		if( dictByUUserIdx.containsKey( key ) ) {
			buff = dictByUUserIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGrpMembId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByIdIdx() ";
		ICFSecSecGrpMemb buff;
		if( dictByPKey.containsKey( SecGrpMembId ) ) {
			buff = dictByPKey.get( SecGrpMembId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpMemb readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuff";
		ICFSecSecGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpMemb lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecSecGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpMemb[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readAllBuff";
		ICFSecSecGrpMemb buff;
		ArrayList<ICFSecSecGrpMemb> filteredList = new ArrayList<ICFSecSecGrpMemb>();
		ICFSecSecGrpMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecGrpMemb instances in the database accessible for the Authorization.
	 */
	public ICFSecSecGrpMemb[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecGrpMemb readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGrpMembId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByIdIdx() ";
		ICFSecSecGrpMemb buff = readDerivedByIdIdx( Authorization,
			SecGrpMembId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecSecGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecGrpMemb[] readBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByClusterIdx() ";
		ICFSecSecGrpMemb buff;
		ArrayList<ICFSecSecGrpMemb> filteredList = new ArrayList<ICFSecSecGrpMemb>();
		ICFSecSecGrpMemb[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpMemb[0] ) );
	}

	public ICFSecSecGrpMemb[] readBuffByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByGroupIdx() ";
		ICFSecSecGrpMemb buff;
		ArrayList<ICFSecSecGrpMemb> filteredList = new ArrayList<ICFSecSecGrpMemb>();
		ICFSecSecGrpMemb[] buffList = readDerivedByGroupIdx( Authorization,
			SecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpMemb[0] ) );
	}

	public ICFSecSecGrpMemb[] readBuffByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByUserIdx() ";
		ICFSecSecGrpMemb buff;
		ArrayList<ICFSecSecGrpMemb> filteredList = new ArrayList<ICFSecSecGrpMemb>();
		ICFSecSecGrpMemb[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpMemb[0] ) );
	}

	public ICFSecSecGrpMemb readBuffByUUserIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByUUserIdx() ";
		ICFSecSecGrpMemb buff = readDerivedByUUserIdx( Authorization,
			ClusterId,
			SecGroupId,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecSecGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific SecGrpMemb buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecGrpMemb[] pageBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpMemb buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecGroupId	The SecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecGrpMemb[] pageBuffByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecGrpMemb[] pageBuffByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecGrpMemb updateSecGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecGrpMemb iBuff )
	{
		CFSecBuffSecGrpMemb Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffSecGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecGrpMemb",
				"Existing record not found",
				"Existing record not found",
				"SecGrpMemb",
				"SecGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecGrpMembByClusterIdxKey existingKeyClusterIdx = (CFSecBuffSecGrpMembByClusterIdxKey)schema.getFactorySecGrpMemb().newByClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecGrpMembByClusterIdxKey newKeyClusterIdx = (CFSecBuffSecGrpMembByClusterIdxKey)schema.getFactorySecGrpMemb().newByClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecGrpMembByGroupIdxKey existingKeyGroupIdx = (CFSecBuffSecGrpMembByGroupIdxKey)schema.getFactorySecGrpMemb().newByGroupIdxKey();
		existingKeyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecBuffSecGrpMembByGroupIdxKey newKeyGroupIdx = (CFSecBuffSecGrpMembByGroupIdxKey)schema.getFactorySecGrpMemb().newByGroupIdxKey();
		newKeyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecBuffSecGrpMembByUserIdxKey existingKeyUserIdx = (CFSecBuffSecGrpMembByUserIdxKey)schema.getFactorySecGrpMemb().newByUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecGrpMembByUserIdxKey newKeyUserIdx = (CFSecBuffSecGrpMembByUserIdxKey)schema.getFactorySecGrpMemb().newByUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecGrpMembByUUserIdxKey existingKeyUUserIdx = (CFSecBuffSecGrpMembByUUserIdxKey)schema.getFactorySecGrpMemb().newByUUserIdxKey();
		existingKeyUUserIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUUserIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		existingKeyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecGrpMembByUUserIdxKey newKeyUUserIdx = (CFSecBuffSecGrpMembByUUserIdxKey)schema.getFactorySecGrpMemb().newByUUserIdxKey();
		newKeyUUserIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUUserIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		newKeyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		if( ! existingKeyUUserIdx.equals( newKeyUUserIdx ) ) {
			if( dictByUUserIdx.containsKey( newKeyUUserIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecGrpMemb",
					"SecGrpMembUUserIdx",
					"SecGrpMembUUserIdx",
					newKeyUUserIdx );
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
						"updateSecGrpMemb",
						"Owner",
						"Owner",
						"SecGrpMembCluster",
						"SecGrpMembCluster",
						"Cluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecGrpMemb",
						"Container",
						"Container",
						"SecGrpMembGroup",
						"SecGrpMembGroup",
						"SecGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdict;

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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpMemb >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUUserIdx.remove( existingKeyUUserIdx );
		dictByUUserIdx.put( newKeyUUserIdx, Buff );

		return(Buff);
	}

	public void deleteSecGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecGrpMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecGrpMembTable.deleteSecGrpMemb() ";
		CFSecBuffSecGrpMemb Buff = ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffSecGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecGrpMemb",
				pkey );
		}
		CFSecBuffSecGrpMembByClusterIdxKey keyClusterIdx = (CFSecBuffSecGrpMembByClusterIdxKey)schema.getFactorySecGrpMemb().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecGrpMembByGroupIdxKey keyGroupIdx = (CFSecBuffSecGrpMembByGroupIdxKey)schema.getFactorySecGrpMemb().newByGroupIdxKey();
		keyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecBuffSecGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecGrpMembByUserIdxKey)schema.getFactorySecGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecGrpMembByUUserIdxKey keyUUserIdx = (CFSecBuffSecGrpMembByUUserIdxKey)schema.getFactorySecGrpMemb().newByUUserIdxKey();
		keyUUserIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUUserIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecGrpMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

		dictByUUserIdx.remove( keyUUserIdx );

	}
	public void deleteSecGrpMembByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecGrpMemb cur;
		LinkedList<CFSecBuffSecGrpMemb> matchSet = new LinkedList<CFSecBuffSecGrpMemb>();
		Iterator<CFSecBuffSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpMemb)(schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() ));
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByClusterIdx( ICFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecBuffSecGrpMembByClusterIdxKey key = (CFSecBuffSecGrpMembByClusterIdxKey)schema.getFactorySecGrpMemb().newByClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGrpMembByClusterIdx( Authorization, key );
	}

	public void deleteSecGrpMembByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpMembByClusterIdxKey argKey )
	{
		CFSecBuffSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpMemb> matchSet = new LinkedList<CFSecBuffSecGrpMemb>();
		Iterator<CFSecBuffSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpMemb)(schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() ));
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecGroupId )
	{
		CFSecBuffSecGrpMembByGroupIdxKey key = (CFSecBuffSecGrpMembByGroupIdxKey)schema.getFactorySecGrpMemb().newByGroupIdxKey();
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGrpMembByGroupIdx( Authorization, key );
	}

	public void deleteSecGrpMembByGroupIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpMembByGroupIdxKey argKey )
	{
		CFSecBuffSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpMemb> matchSet = new LinkedList<CFSecBuffSecGrpMemb>();
		Iterator<CFSecBuffSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpMemb)(schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() ));
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffSecGrpMembByUserIdxKey key = (CFSecBuffSecGrpMembByUserIdxKey)schema.getFactorySecGrpMemb().newByUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecGrpMembByUserIdx( Authorization, key );
	}

	public void deleteSecGrpMembByUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpMembByUserIdxKey argKey )
	{
		CFSecBuffSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpMemb> matchSet = new LinkedList<CFSecBuffSecGrpMemb>();
		Iterator<CFSecBuffSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpMemb)(schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() ));
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByUUserIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		CFLibDbKeyHash256 argSecGroupId,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffSecGrpMembByUUserIdxKey key = (CFSecBuffSecGrpMembByUUserIdxKey)schema.getFactorySecGrpMemb().newByUUserIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		key.setRequiredSecUserId( argSecUserId );
		deleteSecGrpMembByUUserIdx( Authorization, key );
	}

	public void deleteSecGrpMembByUUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpMembByUUserIdxKey argKey )
	{
		CFSecBuffSecGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpMemb> matchSet = new LinkedList<CFSecBuffSecGrpMemb>();
		Iterator<CFSecBuffSecGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpMemb)(schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() ));
			deleteSecGrpMemb( Authorization, cur );
		}
	}
}
