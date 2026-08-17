
// Description: Java 25 in-memory RAM DbIO implementation for SecTentRoleMemb.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecTentRoleMembTable in-memory RAM DbIO implementation
 *	for SecTentRoleMemb.
 */
public class CFSecRamSecTentRoleMembTable
	implements ICFSecSecTentRoleMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecTentRoleMembPKey,
				CFSecBuffSecTentRoleMemb > dictByPKey
		= new HashMap< ICFSecSecTentRoleMembPKey,
				CFSecBuffSecTentRoleMemb >();
	private Map< CFSecBuffSecTentRoleMembByTentRoleIdxKey,
				Map< CFSecBuffSecTentRoleMembPKey,
					CFSecBuffSecTentRoleMemb >> dictByTentRoleIdx
		= new HashMap< CFSecBuffSecTentRoleMembByTentRoleIdxKey,
				Map< CFSecBuffSecTentRoleMembPKey,
					CFSecBuffSecTentRoleMemb >>();
	private Map< CFSecBuffSecTentRoleMembByUserIdxKey,
				Map< CFSecBuffSecTentRoleMembPKey,
					CFSecBuffSecTentRoleMemb >> dictByUserIdx
		= new HashMap< CFSecBuffSecTentRoleMembByUserIdxKey,
				Map< CFSecBuffSecTentRoleMembPKey,
					CFSecBuffSecTentRoleMemb >>();

	public CFSecRamSecTentRoleMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecTentRoleMemb ensureRec(ICFSecSecTentRoleMemb rec) {
		return (((CFSecBuffSecTentRoleMembFactoryService)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb())).ensureRec(rec));
	}

	@Override
	public ICFSecSecTentRoleMemb createSecTentRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMemb iBuff )
	{
		final String S_ProcName = "createSecTentRoleMemb";
		
		CFSecBuffSecTentRoleMemb Buff = (CFSecBuffSecTentRoleMemb)ensureRec(iBuff);
		CFSecBuffSecTentRoleMembPKey pkey = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		pkey.setRequiredSecTentRoleId(Buff.getRequiredSecTentRoleId());
		pkey.setRequiredLoginId(Buff.getRequiredLoginId());
		pkey.setRequiredSecTentRoleId( Buff.getRequiredSecTentRoleId() );
		pkey.setRequiredLoginId( Buff.getRequiredLoginId() );
		Buff.setRequiredContainerRole( pkey.getRequiredSecTentRoleId() );
		Buff.setRequiredParentUser( pkey.getRequiredLoginId() );
		Buff.setRequiredSecTentRoleId( pkey.getRequiredSecTentRoleId() );
		Buff.setRequiredLoginId( pkey.getRequiredLoginId() );
		CFSecBuffSecTentRoleMembByTentRoleIdxKey keyTentRoleIdx = (CFSecBuffSecTentRoleMembByTentRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByTentRoleIdxKey();
		keyTentRoleIdx.setRequiredSecTentRoleId( Buff.getRequiredSecTentRoleId() );

		CFSecBuffSecTentRoleMembByUserIdxKey keyUserIdx = (CFSecBuffSecTentRoleMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByUserIdxKey();
		keyUserIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecTentRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecTentRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecTentRoleMembRole",
						"SecTentRoleMembRole",
						"SecTentRole",
						"SecTentRole",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdictTentRoleIdx;
		if( dictByTentRoleIdx.containsKey( keyTentRoleIdx ) ) {
			subdictTentRoleIdx = dictByTentRoleIdx.get( keyTentRoleIdx );
		}
		else {
			subdictTentRoleIdx = new HashMap< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb >();
			dictByTentRoleIdx.put( keyTentRoleIdx, subdictTentRoleIdx );
		}
		subdictTentRoleIdx.put( pkey, Buff );

		Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecTentRoleMemb.CLASS_CODE) {
				CFSecBuffSecTentRoleMemb retbuff = ((CFSecBuffSecTentRoleMemb)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentRoleMemb readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId,
		String LoginId )
	{
		{	$implJavaOptAtomType$ testSecTentRoleId = SecTentRoleId;
			if (testSecTentRoleId == null) {
				return( null );
			}
		}
		{	$implJavaOptAtomType$ testLoginId = LoginId;
			if (testLoginId == null) {
				return( null );
			}
		}
		CFSecBuffSecTentRoleMembPKey key = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		key.setRequiredSecTentRoleId( SecTentRoleId );
		key.setRequiredLoginId( LoginId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecTentRoleMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readDerived";
		CFSecBuffSecTentRoleMembPKey key = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		key.setRequiredSecTentRoleId( PKey.getRequiredSecTentRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecTentRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRoleMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.lockDerived";
		CFSecBuffSecTentRoleMembPKey key = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		key.setRequiredSecTentRoleId( PKey.getRequiredSecTentRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecTentRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRoleMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readAllDerived";
		ICFSecSecTentRoleMemb[] retList = new ICFSecSecTentRoleMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecTentRoleMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecTentRoleMemb[] readDerivedByTentRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readDerivedByTentRoleIdx";
		CFSecBuffSecTentRoleMembByTentRoleIdxKey key = (CFSecBuffSecTentRoleMembByTentRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByTentRoleIdxKey();

		key.setRequiredSecTentRoleId( SecTentRoleId );
		ICFSecSecTentRoleMemb[] recArray;
		if( dictByTentRoleIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdictTentRoleIdx
				= dictByTentRoleIdx.get( key );
			recArray = new ICFSecSecTentRoleMemb[ subdictTentRoleIdx.size() ];
			Iterator< CFSecBuffSecTentRoleMemb > iter = subdictTentRoleIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdictTentRoleIdx
				= new HashMap< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb >();
			dictByTentRoleIdx.put( key, subdictTentRoleIdx );
			recArray = new ICFSecSecTentRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentRoleMemb[] readDerivedByUserIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readDerivedByUserIdx";
		CFSecBuffSecTentRoleMembByUserIdxKey key = (CFSecBuffSecTentRoleMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByUserIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecTentRoleMemb[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new ICFSecSecTentRoleMemb[ subdictUserIdx.size() ];
			Iterator< CFSecBuffSecTentRoleMemb > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdictUserIdx
				= new HashMap< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new ICFSecSecTentRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentRoleMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readDerivedByIdIdx() ";
		CFSecBuffSecTentRoleMembPKey key = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		key.setRequiredSecTentRoleId( SecTentRoleId );
		key.setRequiredLoginId( LoginId );
		ICFSecSecTentRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRoleMemb readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId,
		String LoginId )
	{
		CFSecBuffSecTentRoleMembPKey key = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		key.setRequiredSecTentRoleId( SecTentRoleId );
		key.setRequiredLoginId( LoginId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecTentRoleMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readRec";
		ICFSecSecTentRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRoleMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecTentRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRoleMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readAllRec";
		ICFSecSecTentRoleMemb buff;
		ArrayList<ICFSecSecTentRoleMemb> filteredList = new ArrayList<ICFSecSecTentRoleMemb>();
		ICFSecSecTentRoleMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRoleMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentRoleMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecTentRoleMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecTentRoleMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecTentRoleMemb[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecTentRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentRoleMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readRecByIdIdx() ";
		ICFSecSecTentRoleMemb buff = readDerivedByIdIdx( Authorization,
			SecTentRoleId,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRoleMemb.CLASS_CODE ) ) {
			return( (ICFSecSecTentRoleMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecTentRoleMemb[] readRecByTentRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readRecByTentRoleIdx() ";
		ICFSecSecTentRoleMemb buff;
		ArrayList<ICFSecSecTentRoleMemb> filteredList = new ArrayList<ICFSecSecTentRoleMemb>();
		ICFSecSecTentRoleMemb[] buffList = readDerivedByTentRoleIdx( Authorization,
			SecTentRoleId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentRoleMemb[0] ) );
	}

	@Override
	public ICFSecSecTentRoleMemb[] readRecByUserIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMemb.readRecByUserIdx() ";
		ICFSecSecTentRoleMemb buff;
		ArrayList<ICFSecSecTentRoleMemb> filteredList = new ArrayList<ICFSecSecTentRoleMemb>();
		ICFSecSecTentRoleMemb[] buffList = readDerivedByUserIdx( Authorization,
			LoginId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentRoleMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecTentRoleMemb buffer instances identified by the duplicate key TentRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecTentRoleId	The SecTentRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentRoleMemb[] pageRecByTentRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId,
		ICFLibKeyHash256 priorSecTentRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByTentRoleIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecTentRoleMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecTentRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentRoleMemb[] pageRecByUserIdx( ICFSecAuthorization Authorization,
		String LoginId,
		ICFLibKeyHash256 priorSecTentRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentRoleMemb updateSecTentRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMemb iBuff )
	{
		CFSecBuffSecTentRoleMemb Buff = (CFSecBuffSecTentRoleMemb)ensureRec(iBuff);
		CFSecBuffSecTentRoleMembPKey pkey = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		pkey = (CFSecBuffSecTentRoleMembPKey)Buff.getPKey();
		CFSecBuffSecTentRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecTentRoleMemb",
				"Existing record not found",
				"Existing record not found",
				"SecTentRoleMemb",
				"SecTentRoleMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecTentRoleMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecTentRoleMembByTentRoleIdxKey existingKeyTentRoleIdx = (CFSecBuffSecTentRoleMembByTentRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByTentRoleIdxKey();
		existingKeyTentRoleIdx.setRequiredSecTentRoleId( existing.getRequiredSecTentRoleId() );

		CFSecBuffSecTentRoleMembByTentRoleIdxKey newKeyTentRoleIdx = (CFSecBuffSecTentRoleMembByTentRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByTentRoleIdxKey();
		newKeyTentRoleIdx.setRequiredSecTentRoleId( Buff.getRequiredSecTentRoleId() );

		CFSecBuffSecTentRoleMembByUserIdxKey existingKeyUserIdx = (CFSecBuffSecTentRoleMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByUserIdxKey();
		existingKeyUserIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecTentRoleMembByUserIdxKey newKeyUserIdx = (CFSecBuffSecTentRoleMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByUserIdxKey();
		newKeyUserIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecTentRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecTentRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecTentRoleMemb",
						"Container",
						"Container",
						"SecTentRoleMembRole",
						"SecTentRoleMembRole",
						"SecTentRole",
						"SecTentRole",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTentRoleIdx.get( existingKeyTentRoleIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTentRoleIdx.containsKey( newKeyTentRoleIdx ) ) {
			subdict = dictByTentRoleIdx.get( newKeyTentRoleIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb >();
			dictByTentRoleIdx.put( newKeyTentRoleIdx, subdict );
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
			subdict = new HashMap< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecTentRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecTentRoleMembTable.deleteSecTentRoleMemb() ";
		CFSecBuffSecTentRoleMemb Buff = (CFSecBuffSecTentRoleMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecTentRoleMembPKey pkey = (CFSecBuffSecTentRoleMembPKey)(Buff.getPKey());
		CFSecBuffSecTentRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecTentRoleMemb",
				pkey );
		}
		CFSecBuffSecTentRoleMembByTentRoleIdxKey keyTentRoleIdx = (CFSecBuffSecTentRoleMembByTentRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByTentRoleIdxKey();
		keyTentRoleIdx.setRequiredSecTentRoleId( existing.getRequiredSecTentRoleId() );

		CFSecBuffSecTentRoleMembByUserIdxKey keyUserIdx = (CFSecBuffSecTentRoleMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByUserIdxKey();
		keyUserIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecTentRoleMembPKey, CFSecBuffSecTentRoleMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTentRoleIdx.get( keyTentRoleIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecTentRoleMembByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId,
		String LoginId )
	{
		CFSecBuffSecTentRoleMembPKey key = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		key.setRequiredSecTentRoleId( SecTentRoleId );
		key.setRequiredLoginId( LoginId );
		deleteSecTentRoleMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentRoleMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMembPKey PKey )
	{
		CFSecBuffSecTentRoleMembPKey key = (CFSecBuffSecTentRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newPKey());
		key.setRequiredSecTentRoleId( PKey.getRequiredSecTentRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		CFSecBuffSecTentRoleMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecTentRoleMemb cur;
		LinkedList<CFSecBuffSecTentRoleMemb> matchSet = new LinkedList<CFSecBuffSecTentRoleMemb>();
		Iterator<CFSecBuffSecTentRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentRoleMemb)(schema.getTableSecTentRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecTentRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentRoleMembByTentRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecTentRoleId )
	{
		CFSecBuffSecTentRoleMembByTentRoleIdxKey key = (CFSecBuffSecTentRoleMembByTentRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByTentRoleIdxKey();
		key.setRequiredSecTentRoleId( argSecTentRoleId );
		deleteSecTentRoleMembByTentRoleIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentRoleMembByTentRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMembByTentRoleIdxKey argKey )
	{
		CFSecBuffSecTentRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentRoleMemb> matchSet = new LinkedList<CFSecBuffSecTentRoleMemb>();
		Iterator<CFSecBuffSecTentRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentRoleMemb)(schema.getTableSecTentRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecTentRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentRoleMembByUserIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecBuffSecTentRoleMembByUserIdxKey key = (CFSecBuffSecTentRoleMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRoleMemb().newByUserIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecTentRoleMembByUserIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentRoleMembByUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleMembByUserIdxKey argKey )
	{
		CFSecBuffSecTentRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentRoleMemb> matchSet = new LinkedList<CFSecBuffSecTentRoleMemb>();
		Iterator<CFSecBuffSecTentRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentRoleMemb)(schema.getTableSecTentRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecTentRoleMemb( Authorization, cur );
		}
	}
}
